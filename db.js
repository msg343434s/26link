const mongoose = require('mongoose');

const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
  console.error('MONGO_URI missing');
  process.exit(1);
}

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB error:', err);
    process.exit(1);
  });

const redirectSchema = new mongoose.Schema({
  key: { type: String, unique: true, index: true },
  destination: { type: String, required: true }
}, { timestamps: true });

const Redirect = mongoose.model('Redirect', redirectSchema);

module.exports = {
  addRedirect: (key, destination) => Redirect.create({ key, destination }),
  getRedirect: (key) => Redirect.findOne({ key }).lean()
};
