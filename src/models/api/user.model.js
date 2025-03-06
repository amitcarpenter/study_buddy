import db from "../../config/db.js";


export const get_user_data_by_email = async (email) => {
    try {
        return await db.query(`SELECT * FROM tbl_users WHERE email = ?`, [email]);
    } catch (error) {
        console.error("Database Error:", error.message);
        throw new Error("Failed to fetch user data.");
    }
};

