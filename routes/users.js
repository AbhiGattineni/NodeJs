const {User, validate} = require('../models/user');
const mongoose = require('mongoose');
const express = require('express');
const router = express.Router();
const _ = require('lodash');
const bcrypt = require('bcrypt');  
const jwt = require('jsonwebtoken'); 

router.post('/', async (req, res) => {
    try {
        const {error} = validate(req.body);
        if (error) return res.status(400).send(error.details[0].message);

        let user = await User.findOne({ email: req.body.email });
        if (user) return res.status(400).send('User already registered.');

        user = new User(_.pick(req.body, ['name', 'email', 'password']));
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
        user = await user.save();

        const token = jwt.sign({_id: user._id}, 'jwtPrivateKey');
        res.header('x-auth-token',token).send(_.pick(user, ['_id', 'name', 'email']));
    } catch (err) {
        // Log the error for debugging
        console.error(err.message);
        // Send a generic error response
        res.status(500).send('An error occurred while processing your request.');
    }
});


module.exports = router;