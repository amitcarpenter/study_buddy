import db from "../config/db.js";

/**=======================user model start =====================================*/
export const isUsersExistsOrNot = async (email) => {
    return db.query("SELECT * FROM tbl_users WHERE email = ?", [email]);
};

export const fetchUsersByActivationCode = async (activationCode) => {
    return db.query("SELECT * FROM tbl_users WHERE code = ?", [activationCode]);
};

export const updateUsersByOtp = async (id) => {
    return db.query(
        `Update tbl_users set isVerified = 1 where id = ?`,
        [id]
    );
};

export const userRegistration = async (data) => {
    return db.query("INSERT INTO tbl_users SET ?", [data]);
};

export const fetchForgotPasswordCodeByCode = async (activationCode) => {
    return db.query("SELECT * FROM tbl_users WHERE forgotPasswordOtp = ?", [activationCode]);
};

export const updateUserForgotPasswordOtp = async (code, email) => {
    const query = "UPDATE tbl_users SET forgotPasswordOtp = ? WHERE email = ?";
    return db.query(query, [code, email]);
};

export const fetchUsersByToken = async (genToken) => {
    return db.query("SELECT * FROM tbl_users WHERE genToken = ?", [genToken]);
};

export const updateUserPassword = async (password, email) => {
    const query = "UPDATE tbl_users SET password = ? WHERE email = ?";
    return db.query(query, [password, email]);
};

export const fetchUsersById = async (id) => {
    return db.query("SELECT * FROM tbl_users WHERE id = ?", [id]);
};

export const changePassword = async (password, id) => {
    const query = "UPDATE tbl_users SET password = ? WHERE id = ?";
    return db.query(query, [password, id]);
};

export const updateUsersProfile = async (updatedFields, id) => {
    const keys = Object.keys(updatedFields);
    const values = Object.values(updatedFields);
    const setClause = keys.map((key) => `${key} = ?`).join(", ");
    values.push(id);
    const query = `UPDATE tbl_users SET ${setClause} WHERE id = ?`;
    return db.query(query, values);
};

export const create_blocked = async (data) => {
    return db.query("INSERT INTO tbl_blockedusers SET ?", [data]);
};

export const unblockedToUsers = async (id) => {
    return db.query(` DELETE FROM tbl_blockedusers WHERE id=?`, [id]);
};

export const fetchBlockedListUsers = async (id) => {
    return db.query(`SELECT * FROM tbl_blockedusers WHERE blocked_from = ? ORDER BY createdAt DESC`, [id]);
};

/**========================model end========================= */
