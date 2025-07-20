(function () {
  "use strict";

  // JQUERY LIGHT BOX
  if (typeof fluidbox === "function") {
    document.querySelectorAll("a").forEach((anchor) => {
      fluidbox(anchor);
    });
  }

  document.querySelectorAll('a[href="#"]').forEach((anchor) => {
    anchor.addEventListener("click", (event) => {
      event.preventDefault();
    });
  });

  // COUNTDOWN TIME
  countdownTime();

  document.querySelectorAll("[data-nav-menu]").forEach((menu) => {
    menu.addEventListener("click", (event) => {
      const visibleHeadArea = menu.getAttribute("data-nav-menu");
      const element = document.querySelector(visibleHeadArea);
      if (element) {
        element.classList.toggle("visible");
      }
    });
  });

  const winWidth = window.innerWidth;
  dropdownMenu(winWidth);

  window.addEventListener("resize", () => {
    dropdownMenu(window.innerWidth);
  });

  // Circular Progress Bar
})();

function countdownTime() {
  if (isExists("#clock")) {
    const clock = document.querySelector("#clock");
    if (clock) {
      const countdown = new Countdown("2025/05/10 15:45", (event) => {
        clock.innerHTML = `
          <div class="time-sec"><span class="title">${event.days}</span> days </div>
          <div class="time-sec"><span class="title">${event.hours}</span> hours </div>
          <div class="time-sec"><span class="title">${event.minutes}</span> minutes </div>
          <div class="time-sec"><span class="title">${event.seconds}</span> seconds </div>
        `;
      });
      countdown.start();
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const rsvpForm = document.querySelector("#rsvp form");
  if (rsvpForm) {
    rsvpForm.addEventListener("submit", (event) => {
      event.preventDefault(); // prevent the form from submitting normally

      const formData = new FormData(event.target);
      const formDataObj = {};
      formData.forEach((value, key) => (formDataObj[key] = value));
      const formBody = new URLSearchParams(formDataObj).toString();
      fetch("/rsvp.php", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formBody,
      })
        .then((response) => response.text())
        .then((data) => {
          // handle the response from the server
          alert("Result: " + data);
        })
        .catch((error) => {
          // handle any errors
          console.error("Error:", error);
          alert("Error: " + error);
        })
        .finally(() => {
          // clean up
          event.target.reset();
        });
    });
  }
});

function isExists(selector) {
  return document.querySelector(selector) !== null;
}

function dropdownMenu(winWidth) {
  if (winWidth > 767) {
    document.querySelectorAll(".main-menu li.drop-down").forEach((item) => {
      const menuAnchor = item.querySelector("a");

      item.addEventListener("mouseover", () => {
        if (menuAnchor) {
          menuAnchor.classList.add("mouseover");
        }
      });

      item.addEventListener("mouseleave", () => {
        if (menuAnchor) {
          menuAnchor.classList.remove("mouseover");
        }
      });
    });
  } else {
    document.querySelectorAll(".main-menu li.drop-down > a").forEach((anchor) => {
      anchor.addEventListener("click", (event) => {
        event.preventDefault();
        const mainMenu = document.querySelector("ul.main-menu");
        if (mainMenu) {
          mainMenu.classList.remove("visible");
        }
        if (anchor.getAttribute("href") === "#") {
          return false;
        }
        if (anchor.classList.contains("mouseover")) {
          anchor.classList.remove("mouseover");
        } else {
          anchor.classList.add("mouseover");
        }
        return false;
      });
    });
  }
}

