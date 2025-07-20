const express = require('express');
const path = require('path');

const PORT = process.env?.PORT || 3000;

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`ToH-Synth running at port ${PORT}`);
});