const bcrypt = require("bcrypt");

const salt = 10;
const adminHashedPassword = bcrypt.hashSync('admin', salt);
const userHashedPassword = bcrypt.hashSync('user', salt);

let usersdata = [
    { id: 1, name: 'Admin', email: 'admin@mail.com', password: adminHashedPassword, role: 'admin' },
    { id: 2, name: 'User', email: 'user@mail.com', password: userHashedPassword, role: 'user' }
]

module.exports = usersdata;