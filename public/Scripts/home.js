console.log("home.js is loaded");

document.addEventListener("DOMContentLoaded", function () {
  const taskCards = document.querySelectorAll(".task-card");

  taskCards.forEach(card => {
    const title = card.querySelector(".task-title");
    const expand = card.querySelector(".task-expand");
    const details = card.nextElementSibling;

    function toggleDetails() {
      if (details && details.classList.contains("task-details")) {
        const isShown = details.classList.contains("show");

        if (isShown) {
          details.classList.remove("show");
          details.classList.add("hidden");
          card.classList.remove("open");
        } else {
          details.classList.add("show");
          details.classList.remove("hidden");
          card.classList.add("open");
        }
      }
    }

    card.addEventListener("click", toggleDetails);
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const btnMale = document.getElementById("btnMale");
  const btnFemale = document.getElementById("btnFemale");

  btnMale.addEventListener("click", () => {
    btnMale.classList.add("active");
    btnFemale.classList.remove("active");
  });

  btnFemale.addEventListener("click", () => {
    btnFemale.classList.add("active");
    btnMale.classList.remove("active");
  });
});

document.addEventListener("DOMContentLoaded", function () {
  const maxXP = 100;

  function updateXPBar(xp, level) {
    const percent = (xp / maxXP) * 100;
    document.getElementById('xpFill').style.width = `${percent}%`;
    document.getElementById('xpInfo').textContent = `XP: ${xp} / ${maxXP}`;
    document.getElementById('level').textContent = `Level: ${level}`;
  }

  function gainXP(amount) {
    fetch('/api/gain-xp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ xpGained: amount })
    })
      .then(res => res.json())
      .then(data => {
        updateXPBar(data.xp, data.level);
        if (data.leveledUp) {
          alert(`Level Up! Je bent nu op level ${data.level}`);
        }
      });
  }


  const completeButtons = document.querySelectorAll(".complete-btn");

  completeButtons.forEach(button => {
    button.addEventListener("click", function (event) {
      event.stopPropagation();

      const taskDetails = button.closest(".task-details");
      const taskCard = taskDetails?.previousElementSibling;
      const taskXp = parseInt(button.dataset.xp, 10) || 0;

      if (!taskCard || isNaN(taskXp)) return;

      addXP(taskXp);

      // Fade-out effect
      taskCard.style.opacity = "0.5";
      taskDetails.style.opacity = "0.5";

      setTimeout(() => {
        taskCard.remove();
        taskDetails.remove();
      }, 2000);
    });
  });

  updateXPBar();
});