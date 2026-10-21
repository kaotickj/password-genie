package com.kaotickj.passwordgenie;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

final class VaultDatabase implements AutoCloseable {
    private final SQLiteDatabase db;
    VaultDatabase(Context context) {
        // noBackupFilesDir keeps the vault out of cloud and device-transfer backups.
        File path = new File(context.getNoBackupFilesDir(), "vault.db");
        boolean fresh = !path.exists();
        db = SQLiteDatabase.openOrCreateDatabase(path, null);
        db.beginTransaction();
        try {
            if (fresh) {
                db.execSQL("CREATE TABLE schema_version (version INTEGER NOT NULL)");
                db.execSQL("INSERT INTO schema_version VALUES (1)");
                db.execSQL("CREATE TABLE master_key (id INTEGER PRIMARY KEY, salt BLOB NOT NULL, hashed_master_key BLOB NOT NULL)");
                db.execSQL("CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, username TEXT NOT NULL, password_encrypted BLOB NOT NULL)");
            }
            try (Cursor c = db.rawQuery("SELECT version FROM schema_version", null)) {
                if (c.getCount() != 1 || !c.moveToFirst() || c.getInt(0) != 1)
                    throw new IllegalStateException("Unsupported vault schema; vault left unchanged");
            }
            db.setTransactionSuccessful();
        } finally { db.endTransaction(); }
    }
    boolean hasMaster() {
        try (Cursor c = db.rawQuery("SELECT id FROM master_key LIMIT 1", null)) { return c.moveToFirst(); }
    }
    void setMaster(String master) throws GeneralSecurityException {
        if (master.isEmpty()) throw new IllegalArgumentException("Enter a master passkey");
        byte[] salt = VaultCrypto.random(16), hash = VaultCrypto.derive(master, salt);
        db.beginTransaction();
        try {
            if (hasMaster()) throw new IllegalStateException("Master password already exists");
            ContentValues values = new ContentValues(); values.put("salt", salt); values.put("hashed_master_key", hash);
            db.insertOrThrow("master_key", null, values); db.setTransactionSuccessful();
        } finally { db.endTransaction(); }
    }
    void verify(String master) throws GeneralSecurityException {
        try (Cursor c = db.rawQuery("SELECT salt, hashed_master_key FROM master_key LIMIT 1", null)) {
            if (!c.moveToFirst() || !MessageDigest.isEqual(VaultCrypto.derive(master, c.getBlob(0)), c.getBlob(1)))
                throw new GeneralSecurityException("Incorrect master password");
        }
    }
    void save(String master, String service, String username, String password) throws GeneralSecurityException {
        verify(master);
        if (service.isEmpty() || username.isEmpty() || password.isEmpty())
            throw new IllegalArgumentException("Platform, username and password are required");
        ContentValues values = new ContentValues(); values.put("service", service); values.put("username", username);
        values.put("password_encrypted", VaultCrypto.encrypt(master, password));
        db.beginTransaction();
        try {
            if (db.update("credentials", values, "service = ?", new String[]{service}) == 0)
                db.insertOrThrow("credentials", null, values);
            db.setTransactionSuccessful();
        } finally { db.endTransaction(); }
    }
    String[] retrieve(String master, String service) throws GeneralSecurityException {
        verify(master);
        try (Cursor c = db.rawQuery("SELECT username, password_encrypted FROM credentials WHERE service = ?", new String[]{service})) {
            if (!c.moveToFirst()) throw new IllegalArgumentException("No credentials found");
            return new String[]{c.getString(0), VaultCrypto.decrypt(master, c.getBlob(1))};
        }
    }
    List<String> services(String master) throws GeneralSecurityException {
        verify(master); List<String> result = new ArrayList<>();
        try (Cursor c = db.rawQuery("SELECT DISTINCT service FROM credentials ORDER BY service", null)) {
            while (c.moveToNext()) result.add(c.getString(0));
        }
        return result;
    }
    public void close() { db.close(); }
}
