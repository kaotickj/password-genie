package com.kaotickj.passwordgenie;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.WindowManager;
import android.widget.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

public final class MainActivity extends Activity {
    private VaultDatabase vault;
    private boolean unlocked;
    private EditText master, platform, username, password, length, result;
    private Button setup;
    private CheckBox letters, digits, punctuation;
    private LinearLayout layout;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll = new ScrollView(this);
        layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad); scroll.addView(layout); setContentView(scroll);
        TextView title = new TextView(this); title.setText("Password Genie 2.1.0"); title.setTextSize(24); layout.addView(title);
        master = field("Master passkey", true);
        master.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int c, int f) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) { lock(); }
            public void afterTextChanged(Editable e) {}
        });
        setup = button("Set master password", () -> {
            if (master.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("Enter a master passkey");
            new AlertDialog.Builder(this).setMessage("Set the initial master password? It cannot be recovered.")
                .setNegativeButton("Cancel", null).setPositiveButton("Set", (d, w) -> run(() -> {
                    vault.setMaster(key()); unlocked = true; setup.setVisibility(android.view.View.GONE); toast("Master password set");
                })).show();
        });
        button("Verify passkey", () -> { lock(); vault.verify(key()); unlocked = true; toast("Vault unlocked"); });
        length = field("Password length", false); length.setInputType(InputType.TYPE_CLASS_NUMBER); length.setText("16");
        letters = check("Letters"); digits = check("Digits"); punctuation = check("Punctuation");
        button("Generate password", () -> { requireUnlocked(); result.setText(VaultCrypto.generate(
            Integer.parseInt(length.getText().toString()), letters.isChecked(), digits.isChecked(), punctuation.isChecked())); });
        platform = field("Platform", false); username = field("Username", false); password = field("Password to save", true);
        button("Choose saved platform", () -> {
            requireUnlocked(); List<String> services = vault.services(key());
            new AlertDialog.Builder(this).setTitle("Saved platforms").setItems(services.toArray(new String[0]),
                (d, which) -> { platform.setText(services.get(which)); result.setText(""); }).show();
        });
        button("Save / update credentials", () -> { requireUnlocked(); vault.save(key(), platform.getText().toString().trim(),
            username.getText().toString().trim(), password.getText().toString()); password.setText(""); toast("Credentials saved"); });
        button("Retrieve credentials", () -> { requireUnlocked(); String[] row = vault.retrieve(key(), platform.getText().toString().trim());
            username.setText(row[0]); result.setText(row[1]); });
        result = field("Generated / retrieved password", true);
        CheckBox show = new CheckBox(this); show.setText("Show result"); layout.addView(show);
        show.setOnCheckedChangeListener((b, checked) -> result.setInputType(InputType.TYPE_CLASS_TEXT
            | (checked ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD : InputType.TYPE_TEXT_VARIATION_PASSWORD)));
        button("Copy result", () -> {
            requireUnlocked(); ClipData clip = ClipData.newPlainText("Password Genie", result.getText().toString());
            android.os.PersistableBundle extras = new android.os.PersistableBundle();
            extras.putBoolean("android.content.extra.IS_SENSITIVE", true); clip.getDescription().setExtras(extras);
            ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(clip); toast("Password copied");
        });
        button("Hash password (SHA-256)", () -> {
            requireUnlocked(); byte[] digest = MessageDigest.getInstance("SHA-256").digest(password.getText().toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(); for (byte b : digest) hex.append(String.format("%02x", b & 255));
            new AlertDialog.Builder(this).setTitle("SHA-256").setMessage(hex.toString()).setPositiveButton("OK", null).show();
        });
        button("Lock vault", () -> { master.setText(""); lock(); });
        TextView help = new TextView(this); help.setText("First run: set a master passkey. Later: verify it to save or retrieve credentials. "
            + "Remember your passkey; it cannot be recovered. The vault stays on this device. Uninstalling deletes it. "
            + "SHA-256 is a fingerprint, not password encryption. GPL v3 — github.com/kaotickj/password-genie"); layout.addView(help);
        try { vault = new VaultDatabase(this); setup.setVisibility(vault.hasMaster() ? android.view.View.GONE : android.view.View.VISIBLE); }
        catch (Exception exc) { new AlertDialog.Builder(this).setTitle("Vault startup error").setMessage(exc.getMessage())
            .setCancelable(false).setPositiveButton("Close", (d, w) -> finish()).show(); }
    }
    private EditText field(String hint, boolean secret) {
        EditText view = new EditText(this); view.setHint(hint); view.setSingleLine(true);
        view.setInputType(InputType.TYPE_CLASS_TEXT | (secret ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS));
        view.setSaveEnabled(false); view.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        layout.addView(view); return view;
    }
    private CheckBox check(String title) { CheckBox c = new CheckBox(this); c.setText(title); c.setChecked(true); layout.addView(c); return c; }
    private interface Action { void execute() throws Exception; }
    private Button button(String title, Action action) { Button b = new Button(this); b.setText(title); b.setAllCaps(false);
        b.setOnClickListener(v -> run(action)); layout.addView(b); return b; }
    private void run(Action action) { try { if (vault != null) action.execute(); }
        catch (Exception exc) { new AlertDialog.Builder(this).setTitle("Password Genie").setMessage(exc.getMessage()).setPositiveButton("OK", null).show(); } }
    private String key() { return master.getText().toString().trim(); }
    private void requireUnlocked() { if (!unlocked) throw new IllegalStateException("Verify or set your master passkey first"); }
    private void toast(String message) { Toast.makeText(this, message, Toast.LENGTH_SHORT).show(); }
    private void lock() { unlocked = false; if (result != null) result.setText(""); if (username != null) username.setText(""); if (password != null) password.setText(""); }
    @Override public void onPause() { super.onPause(); lock(); if (master != null) master.setText(""); }
    @Override public void onDestroy() { if (vault != null) vault.close(); super.onDestroy(); }
}
