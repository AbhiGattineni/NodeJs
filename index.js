const User = require('./routes/users');
const auth = require('./routes/auth');
const express = require('express');
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/NodeJS')
    .then(() => console.log('Connected to MongoDB...'))
    .catch(err => console.error('Could not connect to MongoDB...', err));

const app = express();

app.use(express.json());

app.use('/api/users', User);
app.use('/api/auth', auth);

const port = process.env.PORT || 3000;

app.listen(port, () => console.log(`Listening on port ${port}...`));
