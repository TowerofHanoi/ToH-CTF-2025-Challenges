<?php
include 'lang.php';
?>

<!DOCTYPE html>
<html lang="<?php echo $lang ?>">

<head>
  <title>I&M</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta charset="UTF-8" />

  <link href="https://fonts.googleapis.com/css?family=Playball%7CBitter" rel="stylesheet" />
  <link href="https://fonts.googleapis.com/css?family=Shadows+Into+Light" rel="stylesheet" />

  <link href="common-css/bootstrap.min.css" rel="stylesheet" />
  <link href="common-css/fluidbox.min.css" rel="stylesheet" />
  <link href="common-css/flaticon.css" rel="stylesheet" />
  <link href="common-css/font-icon.css" rel="stylesheet" />
  <link href="css/styles.css" rel="stylesheet" />
  <link href="css/responsive.css" rel="stylesheet" />
</head>

<body>
  <header>
    <div class="container">
      <a class="logo" href="#savethedate"><img src="images/logo.png" height="40" style="width: 40px !important"
          alt="" />
      </a>
      <div class="menu-nav-icon" data-nav-menu="#main-menu">
        <i class="icon icon-bars"></i>
      </div>
      <ul class="main-menu visible-on-click" id="main-menu">
        <li class="drop-down"><a href="#rsvp"><?php echo $i18n['RSVP']; ?></a></li>
        &nbsp;
        <li class="drop-down">
          <a href="?lang=it" class="lang <?php echo $lang == 'it' ? 'mouseover' : ''; ?>">IT</a>
        </li>
        <li class="drop-down">
          <a href="?lang=en" class="lang <?php echo $lang == 'en' ? 'mouseover' : ''; ?>">EN</a>
        </li>
      </ul>
    </div>
  </header>
  <section class="main-slider" id="savethedate">
    <div class="display-table center-text">
      <div class="display-table-cell">
        <div class="slider-content">
          <i class="small-icon icon icon-tie"></i>
          <h5 class="date"><?php echo $i18n['WEDDING DATE']; ?></h5>
          <h3 class="pre-title"><?php echo $i18n['Save The Date']; ?></h3>
          <br />
          <h1 class="title">
            Io_no <i class="icon icon-heart"></i> MrIndeciso
          </h1><br /><br /><br /><br />
        </div>
      </div>
    </div>
  </section>
  <section class="section contact-area" id="rsvp">
    <div class="container">
      <div class="row">
        <div class="col-sm-12 col-md-4 col-lg-6">
          <div class="margin-bottom display-table">
            <div class="display-table-cell">
              <div class="heading heading-section">
                <span class="clone">RSVP</span>
                <h2 class="title"><?php echo $i18n['Contact Us']; ?></h2>
                <i class="icon icon-star"></i>
              </div>
              <p><?php echo $i18n['Contact Us.desc1']; ?></p>
              <br />
              <p><?php echo $i18n['Contact Us.desc2']; ?></p>
              <br />
              <h5>
                Tower |
                <a href="tel:+390123456789" class="phone">+39 012 3456789</a>
              </h5>
              <h5>
                Hanoi |
                <a href="tel:+390123456789" class="phone">+39 012 3456789</a>
              </h5>
              <br />
              <p><?php echo $i18n['Contact Us.address']; ?></p>
            </div>
          </div>
        </div>
        <div class="col-sm-12 col-md-8 col-lg-6">
          <div class="contact-form margin-bottom">
            <h2 class="center-text"><?php echo $i18n['RSVP']; ?></h2>
            <h4 class="pre-title center-text">
              <?php echo $i18n['RSVP.pre-title']; ?>
            </h4>
            <form action="/rsvp.php" method="post">
              <div class="row">
                <div class="col-sm-12 margin-bottom">
                  <label for="name"><?php echo $i18n['Full Name']; ?></label>
                  <input class="name-input" type="text" name="name"
                    placeholder="<?php echo $i18n['Full Name.placeholder'] ?>" />
                </div>
                <div class="col-sm-8 margin-bottom">
                  <label for="email"><?php echo $i18n['Email']; ?></label>
                  <input class="email-input" type="text" name="email"
                    placeholder="<?php echo $i18n['Email.placeholder']?>" />
                </div>
                <div class="col-sm-4 margin-bottom">
                  <label for="guestsnumber"><?php echo $i18n['Guests']; ?></label>
                  <input type="number" value="1" class="event-select" name="guestsnumber" min="1" max="99" />
                </div>
                <div class="col-sm-12 center-text">
                  <button type="submit" class="btn"><b><?php echo $i18n['SEND']; ?></b></button>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </section>
  <footer>
    <div class="container center-text">
      <div class="logo-wrapper">
        <a class="title logo" href="#savethedate">Io_no &amp; <span>MrIndeciso</span> </a>
        <span class="heading-bottom">
          <i class="icon-star"></i>
        </span>
      </div>
      <ul>
        <li><a href="#savethedate"><?php echo $i18n['HOME']; ?></a></li>
        <li><a href="#rsvp"><?php echo $i18n['RSVP']; ?></a></li>
      </ul>
    </div>
  </footer>
  <script src="js/scripts.js"></script>
  <script id="smoothness">
  let headerHeight = document.querySelector("header").clientHeight; // 86
  document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
      anchor.addEventListener("click", function(e) {
        e.preventDefault();

        let target = document.querySelector(this.getAttribute("href"));
        if (target) {
          window.scrollTo({
            top: target.offsetTop - headerHeight,
            behavior: "smooth"
          });
        }
      });
    });
  });

  let savethedateHeight = document.querySelector("#savethedate").clientHeight; // 600
  window.addEventListener("scroll", function() {
    let scrollTop = window.scrollY;

    if (scrollTop > savethedateHeight - headerHeight * 2) {
      document.querySelector("header").classList.add("sticky");
      document.querySelector("header.sticky:after").style.opacity = "1";
    } else {
      document.querySelector("header").classList.remove("sticky");
      document.querySelector("header.sticky:after").style.opacity = "0";
    }
  });
  </script>
</body>

</html>