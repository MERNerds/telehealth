const { Schema, model } = require('mongoose');
const bcrypt = require('bcrypt')

const clinicianSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            match: [/.+@.+\..+/, 'Must match an email address!']
        },
        password: {
            type: String,
            required: true,
            minlength: 8
        },
        patients: [
            {
                type: Schema.Types.ObjectId,
                ref: 'patient'
            }
        ]
    },
    {
        toJSON: {
            virtuals: true
        }
    }
);

clinicianSchema.pre('save', async function (next) {
    if (this.isNew || this.isModified('password')) {
        const saltRounds = 10;
        this.password = await bcrypt.hash(this.password, saltRounds);
    }

    next();
});

// compare the incoming password with the hashed password
clinicianSchema.methods.isCorrectPassword = async function (password) {
    return bcrypt.compare(password, this.password);
};


const User = model('User', userSchema);

module.exports = User;