const { visit } = require('./bot.js');
const express = require('express');

const app = express();
const PORT = 5001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send(`
    <body>
    <form method="POST" action="/visit">
      <label for="url">Enter URL:</label>
      <input type="url" id="url" name="url" required>
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post('/visit', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string' || !url.startsWith('http')) {
    return res.status(400).send('Invalid URL');
  }

  try {
    await visit(url);

    res.send('URL visited successfully!');
  } catch (error) {
    console.error('Error visiting URL:', error);
    res.status(500).send('Failed to visit the URL.');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://bot:${PORT}`);
});