const { firefox } = require('playwright');
const fs = require('fs-extra');

console.log(`[+] Starting bot...`);

const HOST = process.env.APP_HOST;
const PORT = process.env.APP_PORT;
const FLAG = process.env.FLAG || 'toh{this_is_a_sample_flag}';
const PROFILE_PATH = process.env.PROFILE_PATH || '/home/user/firefox-profile';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const visit = async (url) => {
  console.log(`[+] Starting Playwright bot to visit: ${url}`);
  // copy profile to a temporary location
  const tempProfilePath = `/tmp/playwright-profile-${Date.now()}`;
  
  try {
    await fs.copy(PROFILE_PATH, tempProfilePath);
    console.log(`[+] Copied profile to temporary location: ${tempProfilePath}`);
  } catch (err) {
    console.error(`[-] Error copying profile: ${err}`);
    return;
  }

  let context = null;
  let page = null;

  try {
    // Launch Firefox with custom profile using persistent context
    context = await firefox.launchPersistentContext(tempProfilePath, {
      headless: true,
      ignoreHTTPSErrors: true,
      acceptDownloads: false,
      firefoxUserPrefs: {
        'signon.rememberSignons': true,
        'signon.autofillForms': true,
      }
    });

    // Create new page from the context
    page = await context.newPage();

    // login to the application and upload settings
    const loginUrl = `https://${HOST}:${PORT}/login`;
    console.log(`[+] Visiting login page: ${loginUrl}`);
    await page.goto(loginUrl, { waitUntil: 'networkidle' });

    console.log(`[+] Playwright Firefox launched successfully with persistent context`);
    await page.waitForSelector('input[name="username"]', { timeout: 5000 });
    // Fill in login form
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'testpaswd');
    await page.click('button[type="submit"]');

    // Wait for navigation after login
    await sleep(1000); // Wait for 1 second to ensure login is processed

    console.log(`[+] Logged in successfully`);

    await page.click('a:has-text("Settings")');
    // Fill in settings form
    await page.waitForSelector('input[name="displayName"]', { timeout: 5000 });
    console.log(`[+] Filling settings form with flag: ${FLAG}`);
    await page.fill('input[name="displayName"]', FLAG);
    
    // display color is a type color
    await page.fill('input[name="displayColor"]', '#ff0000'); // Red
    await page.click('button[type="submit"]');
    await sleep(1000); // Wait for settings to be saved
    // Wait for settings to be saved
    console.log(`[+] Settings saved successfully`);

    // Now visit the target URL
    console.log(`[+] Visiting target URL: ${url}`);
    await page.goto(url, {
      timeout: 10000,
      waitUntil: 'networkidle'
    });
    
    // Wait a bit on the final page
    await sleep(10 * 1000);

    // console.log(`[+] Successfully visited target URL`);

  } catch (err) {
    console.error(`[-] Error visiting URL: ${err}`);
    console.error(`[-] Error stack: ${err.stack}`);
  } finally {
    try {
      if (page) {
        await page.close();
      }
      if (context) {
        await context.close();
      }
    } catch (e) {
      console.error(`[-] Error cleaning up: ${e.message}`);
    }
  }
};

module.exports = { visit };
