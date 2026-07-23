//! Fossroot GUI (egui/eframe). Same core as the CLI: verify first, show a full
//! diff, change nothing without an explicit click.

use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use fossroot_core::store::{platform, Location, StoreKind, SystemStore, TrustStore};
use fossroot_core::{diff, Bundle, CertStatus, DiffReport};

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1020.0, 680.0])
            .with_min_inner_size([760.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Fossroot — DoD PKI trust store manager",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_pixels_per_point(1.15);
            Ok(Box::new(App::new()))
        }),
    )
}

struct Data {
    bundle: Bundle,
    user: DiffReport,
    machine: DiffReport,
}

enum Msg {
    // Boxed: Data is large, so keep the enum variants uniform in size.
    Loaded(Box<Result<Data, String>>),
    Applied(Result<String, String>),
}

// Ready(Data) is the steady state and dominates the app's lifetime, so the size
// gap versus the transient Loading/Failed variants is not worth a heap indirection.
#[allow(clippy::large_enum_variant)]
enum State {
    Loading,
    Ready(Data),
    Failed(String),
}

struct App {
    state: State,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: bool,
    last_action: Option<Result<String, String>>,
    confirm_remove: bool,
    show_certs: bool,
}

fn load_data() -> Result<Data, String> {
    let bundle = Bundle::fetch().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();
    let store = platform();
    let mut reports = Vec::new();
    for location in [Location::CurrentUser, Location::LocalMachine] {
        let in_root = store
            .list(SystemStore {
                location,
                kind: StoreKind::Root,
            })
            .map_err(|e| e.to_string())?;
        let in_ca = store
            .list(SystemStore {
                location,
                kind: StoreKind::Ca,
            })
            .map_err(|e| e.to_string())?;
        reports.push(diff::diff(&bundle.certs, &in_root, &in_ca, now));
    }
    let machine = reports.pop().unwrap();
    let user = reports.pop().unwrap();
    Ok(Data {
        bundle,
        user,
        machine,
    })
}

fn apply_install(location: Location) -> Result<String, String> {
    let data = load_data()?;
    let report = match location {
        Location::CurrentUser => &data.user,
        Location::LocalMachine => &data.machine,
    };
    let store = platform();
    let mut added = 0usize;
    for e in report
        .entries
        .iter()
        .filter(|e| e.status == CertStatus::Missing)
    {
        store
            .add(
                SystemStore {
                    location,
                    kind: e.store,
                },
                &e.cert.der,
            )
            .map_err(|e| e.to_string())?;
        added += 1;
    }
    Ok(format!("Installed {added} certificates"))
}

fn apply_remove(location: Location) -> Result<String, String> {
    let data = load_data()?;
    let report = match location {
        Location::CurrentUser => &data.user,
        Location::LocalMachine => &data.machine,
    };
    let store = platform();
    let mut removed = 0usize;
    for e in report
        .entries
        .iter()
        .filter(|e| e.status == CertStatus::Installed)
    {
        if store
            .remove_by_sha1(
                SystemStore {
                    location,
                    kind: e.store,
                },
                &e.cert.sha1,
            )
            .map_err(|e| e.to_string())?
        {
            removed += 1;
        }
    }
    Ok(format!("Removed {removed} certificates"))
}

impl App {
    fn new() -> Self {
        let (tx, rx) = channel();
        let app = App {
            state: State::Loading,
            tx,
            rx,
            busy: false,
            last_action: None,
            confirm_remove: false,
            show_certs: true,
        };
        app.spawn_load();
        app
    }

    fn spawn_load(&self) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Loaded(Box::new(load_data())));
        });
    }

    fn spawn_apply(&mut self, f: fn(Location) -> Result<String, String>, location: Location) {
        self.busy = true;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = f(location);
            let _ = tx.send(Msg::Applied(result));
            let _ = tx.send(Msg::Loaded(Box::new(load_data())));
        });
    }
}

fn status_chip(ui: &mut egui::Ui, status: CertStatus) {
    let (text, color) = match status {
        CertStatus::Installed => ("installed", Color32::from_rgb(0x2e, 0x9e, 0x5b)),
        CertStatus::Missing => ("missing", Color32::from_rgb(0xd9, 0x77, 0x06)),
        CertStatus::Expired => ("expired", Color32::GRAY),
    };
    ui.label(RichText::new(text).color(color).monospace());
}

fn summary_card(ui: &mut egui::Ui, title: &str, report: &DiffReport) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).strong());
            let usable = report.installed + report.missing;
            ui.label(
                RichText::new(format!("{}/{}", report.installed, usable))
                    .size(26.0)
                    .color(if report.missing == 0 {
                        Color32::from_rgb(0x2e, 0x9e, 0x5b)
                    } else {
                        Color32::from_rgb(0xd9, 0x77, 0x06)
                    }),
            );
            let mut sub = format!("{} missing", report.missing);
            if !report.stale.is_empty() {
                sub.push_str(&format!(", {} stale", report.stale.len()));
            }
            ui.label(RichText::new(sub).weak());
        });
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Loaded(result) => {
                    self.busy = false;
                    self.state = match *result {
                        Ok(data) => State::Ready(data),
                        Err(e) => State::Failed(e),
                    };
                }
                Msg::Applied(result) => self.last_action = Some(result),
            }
        }
        if matches!(self.state, State::Loading) || self.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("Fossroot").strong());
                ui.label(RichText::new("open-source DoD PKI trust store manager").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::widgets::global_theme_preference_switch(ui);
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("⟳ Refresh"))
                        .clicked()
                    {
                        self.state = State::Loading;
                        self.spawn_load();
                    }
                });
            });
            ui.add_space(6.0);
        });

        // Actions are recorded here and executed after the panel closure, since
        // the closure holds an immutable borrow of self.state.
        enum Action {
            Reload,
            Install(Location),
            AskRemove,
        }
        let mut action: Option<Action> = None;
        let mut show_certs = self.show_certs;
        let busy = self.busy;

        egui::CentralPanel::default().show(ctx, |ui| match &self.state {
            State::Loading => {
                ui.vertical_centered(|ui| {
                    ui.add_space(120.0);
                    ui.spinner();
                    ui.add_space(8.0);
                    ui.label("Fetching the latest DoD bundle from dl.dod.cyber.mil and verifying it…");
                });
            }
            State::Failed(err) => {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.colored_label(Color32::from_rgb(0xcc, 0x33, 0x33), "Verification or download failed — nothing was changed.");
                    ui.add_space(6.0);
                    ui.label(RichText::new(err).monospace());
                    ui.add_space(10.0);
                    if ui.button("Try again").clicked() {
                        action = Some(Action::Reload);
                    }
                });
            }
            State::Ready(data) => {
                let bundle = &data.bundle;
                // --- verification banner ---
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("DoD PKI bundle v{}", bundle.version)).strong());
                        ui.label(format!("· {} certificates ·", bundle.certs.len()));
                        if bundle.verify.manifest_signed {
                            ui.label(
                                RichText::new("✔ DISA manifest signature verified")
                                    .color(Color32::from_rgb(0x2e, 0x9e, 0x5b)),
                            );
                        }
                        ui.label(
                            RichText::new(format!(
                                "✔ all chains verify to pinned roots ({})",
                                bundle.verify.anchored_roots.join(", ")
                            ))
                            .color(Color32::from_rgb(0x2e, 0x9e, 0x5b)),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("zip sha256:").weak());
                        ui.label(RichText::new(&bundle.zip_sha256).monospace().size(11.0));
                    });
                });
                ui.add_space(8.0);

                // --- summary cards ---
                ui.horizontal(|ui| {
                    summary_card(ui, "Current User", &data.user);
                    summary_card(ui, "Local Machine", &data.machine);
                });
                ui.add_space(8.0);

                // --- actions ---
                ui.horizontal(|ui| {
                    let missing_user = data.user.missing;
                    if ui
                        .add_enabled(
                            !busy && missing_user > 0,
                            egui::Button::new(format!("Install {missing_user} missing (Current User)")),
                        )
                        .on_hover_text("No admin needed. Windows will ask you to confirm each new root certificate.")
                        .clicked()
                    {
                        action = Some(Action::Install(Location::CurrentUser));
                    }
                    let missing_machine = data.machine.missing;
                    if ui
                        .add_enabled(
                            !busy && missing_machine > 0 && is_elevated(),
                            egui::Button::new(format!("Install {missing_machine} missing (Machine)")),
                        )
                        .on_hover_text(if is_elevated() {
                            "Installs into the Local Machine stores."
                        } else {
                            "Requires administrator — use 'Relaunch as admin'."
                        })
                        .clicked()
                    {
                        action = Some(Action::Install(Location::LocalMachine));
                    }
                    if !is_elevated() && ui.add_enabled(!busy, egui::Button::new("🛡 Relaunch as admin")).clicked() {
                        relaunch_elevated();
                    }
                    if ui
                        .add_enabled(!busy && data.user.installed > 0, egui::Button::new("Remove all (Current User)"))
                        .clicked()
                    {
                        action = Some(Action::AskRemove);
                    }
                    if busy {
                        ui.spinner();
                    }
                    if let Some(result) = &self.last_action {
                        match result {
                            Ok(msg) => ui.colored_label(Color32::from_rgb(0x2e, 0x9e, 0x5b), msg),
                            Err(e) => ui.colored_label(Color32::from_rgb(0xcc, 0x33, 0x33), e),
                        };
                    }
                });
                ui.add_space(8.0);

                // --- certificate table ---
                ui.checkbox(&mut show_certs, "Show certificate details");
                if show_certs {
                    ui.add_space(4.0);
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::remainder().at_least(220.0))
                        .column(Column::auto().at_least(50.0))
                        .column(Column::auto().at_least(80.0))
                        .column(Column::auto().at_least(80.0))
                        .column(Column::auto().at_least(80.0))
                        .header(22.0, |mut header| {
                            for title in ["Certificate", "Store", "Expires", "User", "Machine"] {
                                header.col(|ui| {
                                    ui.label(RichText::new(title).strong());
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(20.0, data.user.entries.len(), |mut row| {
                                let i = row.index();
                                let ue = &data.user.entries[i];
                                let me = &data.machine.entries[i];
                                row.col(|ui| {
                                    ui.label(ue.cert.display_name())
                                        .on_hover_text(format!(
                                            "{}\nsha256 {}",
                                            ue.cert.subject,
                                            fossroot_core::certs::hex(&ue.cert.sha256)
                                        ));
                                });
                                row.col(|ui| {
                                    ui.label(match ue.store {
                                        StoreKind::Root => "ROOT",
                                        StoreKind::Ca => "CA",
                                    });
                                });
                                row.col(|ui| {
                                    ui.label(fossroot_core::certs::format_unix(ue.cert.not_after));
                                });
                                row.col(|ui| status_chip(ui, ue.status));
                                row.col(|ui| status_chip(ui, me.status));
                            });
                        });
                }
            }
        });

        self.show_certs = show_certs;
        match action {
            Some(Action::Reload) => {
                self.state = State::Loading;
                self.spawn_load();
            }
            Some(Action::Install(location)) => self.spawn_apply(apply_install, location),
            Some(Action::AskRemove) => self.confirm_remove = true,
            None => {}
        }

        // --- remove confirmation modal ---
        if self.confirm_remove {
            egui::Window::new("Remove all DoD certificates?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        "This removes every certificate from the current DISA bundle from your\n\
                         Current User stores — exactly what Fossroot manages, nothing else.\n\
                         You can reinstall at any time.",
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.confirm_remove = false;
                        }
                        if ui
                            .button(
                                RichText::new("Remove them")
                                    .color(Color32::from_rgb(0xcc, 0x33, 0x33)),
                            )
                            .clicked()
                        {
                            self.confirm_remove = false;
                            self.spawn_apply(apply_remove, Location::CurrentUser);
                        }
                    });
                });
        }
    }
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(windows)]
fn relaunch_elevated() {
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    if let Ok(exe) = std::env::current_exe() {
        let exe_w: Vec<u16> = exe
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR(exe_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
        }
    }
}

#[cfg(not(windows))]
fn relaunch_elevated() {}
