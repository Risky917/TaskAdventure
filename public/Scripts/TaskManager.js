//deleting The  buttons accept and delete upon accepting
document.addEventListener('DOMContentLoaded', function () {
    const acceptForms = document.querySelectorAll('.accept-button');

    acceptForms.forEach(button => {
      button.addEventListener('click', function (e) {
        e.preventDefault(); 
        const formContainer = button.closest('.task-item');

        const forms = formContainer.querySelectorAll('form');
        forms.forEach(form => {
          form.style.display = 'none';
        });
      });
    });
  });

