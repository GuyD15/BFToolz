const bcrypt = require("bcryptjs");

const password = "BFLogin1!"; // Replace with the desired password

bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;
    console.log("Hashed password:", hash);
});