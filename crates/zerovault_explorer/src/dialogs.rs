use std::sync::{Arc, Mutex};
use eframe::{egui, Frame};
use egui::{Align, Button, CentralPanel, Color32, Context, Key, Layout, RichText, TextEdit, Vec2};

/// Simple dialog for entering a new password with confirmation
pub fn get_new_password() -> Result<String, String> {
    let password = Arc::new(Mutex::new(String::new()));
    let result = password.clone();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 220.0])
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    
    match eframe::run_native(
        "ZeroVault - Set Password",
        options,
        Box::new(|_cc| Box::new(NewPasswordDialog::new(password))),
    ) {
        Ok(_) => {}
        Err(e) => return Err(format!("Failed to create dialog: {}", e)),
    }
    
    // Extract the result
    let pw = result.lock().unwrap().clone();
    Ok(pw)
}

/// Simple dialog for entering an existing password
pub fn get_existing_password() -> Result<String, String> {
    let password = Arc::new(Mutex::new(String::new()));
    let result = password.clone();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 160.0])
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    
    match eframe::run_native(
        "ZeroVault - Enter Password",
        options,
        Box::new(|_cc| Box::new(PasswordDialog::new(password))),
    ) {
        Ok(_) => {}
        Err(e) => return Err(format!("Failed to create dialog: {}", e)),
    }
    
    // Extract the result
    let pw = result.lock().unwrap().clone();
    Ok(pw)
}

/// Show a simple success message dialog
pub fn show_success(title: &str, message: &str) {
    let title_owned = title.to_string();
    let message_owned = message.to_string();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 150.0])
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    
    if let Err(e) = eframe::run_native(
        &title_owned,
        options,
        Box::new(move |_cc| Box::new(MessageDialog::new(message_owned, true))),
    ) {
        eprintln!("Failed to show success dialog: {}", e);
    }
}

/// Show a simple error message dialog
pub fn show_error(title: &str, message: &str) {
    let title_owned = title.to_string();
    let message_owned = message.to_string();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 150.0])
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    
    if let Err(e) = eframe::run_native(
        &title_owned,
        options,
        Box::new(move |_cc| Box::new(MessageDialog::new(message_owned, false))),
    ) {
        eprintln!("Failed to show error dialog: {}", e);
    }
}

/// Show a confirmation dialog and return true if confirmed
pub fn show_confirmation(title: &str, message: &str) -> bool {
    let confirmed = Arc::new(Mutex::new(false));
    let result = confirmed.clone();
    
    // Create owned strings
    let title_owned = title.to_string();
    let message_owned = message.to_string();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 150.0])
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    
    if let Err(e) = eframe::run_native(
        &title_owned,
        options,
        Box::new({
            let confirmed = confirmed.clone();
            move |_cc| Box::new(ConfirmationDialog::new(message_owned, confirmed))
        }),
    ) {
        eprintln!("Failed to show confirmation dialog: {}", e);
        return false;
    }
    
    // Extract the result
    let confirmed = *result.lock().unwrap();
    confirmed
}

/// Dialog for entering and confirming a new password
struct NewPasswordDialog {
    password: String,
    confirm_password: String,
    error_message: String,
    result: Arc<Mutex<String>>,
    done: bool,
}

impl NewPasswordDialog {
    fn new(result: Arc<Mutex<String>>) -> Self {
        Self {
            password: String::new(),
            confirm_password: String::new(),
            error_message: String::new(),
            result,
            done: false,
        }
    }
}

impl eframe::App for NewPasswordDialog {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.heading("Enter encryption password");
                ui.add_space(15.0);
                
                ui.label("Password:");
                let password_edit = TextEdit::singleline(&mut self.password)
                    .password(true)
                    .desired_width(350.0)
                    .hint_text("Enter a strong password");
                ui.add(password_edit);
                
                ui.add_space(5.0);
                
                ui.label("Confirm password:");
                let confirm_edit = TextEdit::singleline(&mut self.confirm_password)
                    .password(true)
                    .desired_width(350.0)
                    .hint_text("Re-enter the same password");
                ui.add(confirm_edit);
                
                ui.add_space(5.0);
                
                if !self.error_message.is_empty() {
                    ui.label(RichText::new(&self.error_message).color(Color32::RED));
                }
                
                ui.add_space(5.0);
                
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Cancel").clicked() {
                        self.done = true;
                    }
                    
                    if ui.button("OK").clicked() {
                        if self.password.is_empty() {
                            self.error_message = "Password cannot be empty".to_string();
                        } else if self.password != self.confirm_password {
                            self.error_message = "Passwords do not match".to_string();
                        } else if self.password.len() < 8 {
                            self.error_message = "Password should be at least 8 characters".to_string();
                        } else {
                            // Password is valid, return it
                            *self.result.lock().unwrap() = self.password.clone();
                            self.done = true;
                        }
                    }
                });
            });
        });
        
        // Handle Enter key to press OK
        if ctx.input(|i| i.key_pressed(Key::Enter)) && !self.password.is_empty() && self.password == self.confirm_password {
            *self.result.lock().unwrap() = self.password.clone();
            self.done = true;
        }
        
        // Handle Escape key to cancel
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.done = true;
        }
    }
}

/// Dialog for entering an existing password
struct PasswordDialog {
    password: String,
    error_message: String,
    result: Arc<Mutex<String>>,
    done: bool,
}

impl PasswordDialog {
    fn new(result: Arc<Mutex<String>>) -> Self {
        Self {
            password: String::new(),
            error_message: String::new(),
            result,
            done: false,
        }
    }
}

impl eframe::App for PasswordDialog {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.heading("Enter decryption password");
                ui.add_space(15.0);
                
                ui.label("Password:");
                let password_edit = TextEdit::singleline(&mut self.password)
                    .password(true)
                    .desired_width(350.0)
                    .hint_text("Enter the password for this vault");
                ui.add(password_edit);
                
                ui.add_space(5.0);
                
                if !self.error_message.is_empty() {
                    ui.label(RichText::new(&self.error_message).color(Color32::RED));
                }
                
                ui.add_space(10.0);
                
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Cancel").clicked() {
                        self.done = true;
                    }
                    
                    if ui.button("OK").clicked() {
                        if self.password.is_empty() {
                            self.error_message = "Password cannot be empty".to_string();
                        } else {
                            // Password provided, return it
                            *self.result.lock().unwrap() = self.password.clone();
                            self.done = true;
                        }
                    }
                });
            });
        });
        
        // Handle Enter key to press OK
        if ctx.input(|i| i.key_pressed(Key::Enter)) && !self.password.is_empty() {
            *self.result.lock().unwrap() = self.password.clone();
            self.done = true;
        }
        
        // Handle Escape key to cancel
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.done = true;
        }
    }
}

/// Dialog for displaying a message
struct MessageDialog {
    message: String,
    is_success: bool,
    done: bool,
}

impl MessageDialog {
    fn new(message: String, is_success: bool) -> Self {
        Self {
            message,
            is_success,
            done: false,
        }
    }
}

impl eframe::App for MessageDialog {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                
                // Icon and header
                if self.is_success {
                    ui.heading(RichText::new("✓ Success").color(Color32::GREEN));
                } else {
                    ui.heading(RichText::new("⨯ Error").color(Color32::RED));
                }
                
                ui.add_space(10.0);
                
                // Message
                ui.label(&self.message);
                
                ui.add_space(15.0);
                
                // OK button
                let btn = Button::new("OK").min_size(Vec2::new(80.0, 30.0));
                if ui.add_sized([80.0, 30.0], btn).clicked() {
                    self.done = true;
                }
            });
        });
        
        // Handle Enter or Escape to close
        if ctx.input(|i| i.key_pressed(Key::Enter) || i.key_pressed(Key::Escape)) {
            self.done = true;
        }
    }
}

/// Dialog for confirmation (Yes/No)
struct ConfirmationDialog {
    message: String,
    result: Arc<Mutex<bool>>,
    done: bool,
}

impl ConfirmationDialog {
    fn new(message: String, result: Arc<Mutex<bool>>) -> Self {
        Self {
            message,
            result,
            done: false,
        }
    }
}

impl eframe::App for ConfirmationDialog {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.heading("Confirmation");
                
                ui.add_space(10.0);
                
                // Message
                ui.label(&self.message);
                
                ui.add_space(15.0);
                
                // Buttons
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let no_btn = Button::new("No").min_size(Vec2::new(80.0, 30.0));
                    if ui.add_sized([80.0, 30.0], no_btn).clicked() {
                        *self.result.lock().unwrap() = false;
                        self.done = true;
                    }
                    
                    ui.add_space(10.0);
                    
                    let yes_btn = Button::new("Yes").min_size(Vec2::new(80.0, 30.0));
                    if ui.add_sized([80.0, 30.0], yes_btn).clicked() {
                        *self.result.lock().unwrap() = true;
                        self.done = true;
                    }
                });
            });
        });
        
        // Handle Enter for Yes
        if ctx.input(|i| i.key_pressed(Key::Enter)) {
            *self.result.lock().unwrap() = true;
            self.done = true;
        }
        
        // Handle Escape for No
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            *self.result.lock().unwrap() = false;
            self.done = true;
        }
    }
}