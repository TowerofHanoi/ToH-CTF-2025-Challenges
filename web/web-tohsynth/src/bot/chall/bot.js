const express = require('express');
const puppeteer = require('puppeteer');
const path = require('path');

const flag = process.env['FLAG'] ?? 'toh{REDACTED}';
const PORT = process.env?.PORT || 3001;
const challDomain = process.env?.CHALL_DOMAIN || 'localhost';

const app = express();
app.use(express.urlencoded({ extended: false }));

app.post('/play', async (req, res) => {
    let { url } = req.body;
    
    if (!url) {
        return res.status(400).send('Invalid URL');
    }

    let browser;
    try {
        console.info(`[+] Visiting: ${url}`);
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox'
            ]
        });
        
        const page = await browser.newPage();

        await page.setCookie({
            name: 'flag',
            value: flag,
            domain: challDomain
        });
        console.info('[+] Cookie set successfully');
        
        await page.goto(url);
        console.info('[+] Navigate to URL successful');
        
        await page.setViewport({ width: 1280, height: 720 });
        console.info('[+] Viewport set successfully');

        await page.locator(".btnPlay").click();
        console.info('[+] Clicked play button successfully');

        await page.evaluate(() => {
            return new Promise(resolve => setTimeout(resolve, 5000));
        });
        console.info('[+] Waited for 5 seconds after clicking play button');

        await browser.close();
        console.info('[+] Bot finished successfully');
        
        res.send('URL visited by bot!');
    } catch (err) {
        console.error(`[!] Error visiting URL:`, err);
        if (browser) await browser.close();
        res.status(500).send('Bot error visiting URL');
    }
});

app.get('/', (req, res) => {
    res.send(`
        <h2>ToH-Synth Bot</h2>
        <form method="POST" action="/play">
        <input type="text" name="url" placeholder="http://tohsynth/?synthdata=..." style="width: 500px;" />
        <button type="submit">Submit</button>
        </form>
    `);
});

app.listen(PORT, () => {
    console.log(`ToH-Synth Bot running at port ${PORT}`);
});