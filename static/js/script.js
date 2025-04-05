document.addEventListener('DOMContentLoaded', function() {
    var overlay = document.getElementById('overlay');
    var signupFormContainer = document.getElementById('signup-form-container');
    var signupBtn = document.getElementById('signup-btn');
    var loginBtn = document.getElementById('login-btn');
    var startBtn = document.getElementById('start-btn');
    var loginStart = document.getElementById('login-start');
    var closeBtn_1 = document.getElementById('close-btn_1');
    var closeBtn_3 = document.getElementById('close-btn_3');
    var mainContent = document.getElementById('main-content');
    var confirmationPage = document.getElementById('confirmation-page');
    var loginFormContainer = document.getElementById('login-form-container'); // Nouvelle section pour le formulaire de connexion

    
    signupBtn.addEventListener('click', function() {
        console.log('Signup');
        overlay.style.display = 'block';
        signupFormContainer.style.display = 'block';
        //mainContent.classList.add('blur');
    });

    startBtn.addEventListener('click', function() {
        overlay.style.display = 'block';
        signupFormContainer.style.display = 'block';
    })

    loginBtn.addEventListener('click', function() {
        overlay.style.display = 'block';
        loginFormContainer.style.display = 'block';
        //mainContent.classList.add('blur');
    });

    loginStart.addEventListener('click', function() {
        overlay.style.display = 'block';
        signupFormContainer.style.display = 'none';
        loginFormContainer.style.display = 'block';
        console.log('Bouton cliqué')
    });


    // Fonction pour gérer la fermeture des boutons
    function closeButtons(buttonId) {
        overlay.style.display = 'none';
        signupFormContainer.style.display = 'none';
        loginFormContainer.style.display = 'none';
        confirmationPage.style.display = 'none';
        mainContent.classList.remove('blur');
        
        if (buttonId === 'close-btn_3') {
            loginFormContainer.style.display = 'none';
        }
    }

    // Ajouter des écouteurs d'événements pour les boutons de fermeture
    closeBtn_1.addEventListener('click', function() {
        closeButtons('close-btn_1');
    });

    closeBtn_3.addEventListener('click', function() {
        closeButtons('close-btn_3');
    });
/*
    var data_send = true;

    if (data_send ){
        var confirmationPage = document.getElementById('confirmation-page');
        var overlay = document.getElementById('overlay');
        var mainContent = document.getElementById('main-content');
    
        // Afficher le fond sombre à la page principale
        overlay.style.display = 'block';
    
        // Afficher le bloc de confirmation après 1 seconde
        setTimeout(function() {
            confirmationPage.style.display = 'block';
        }, 1000);
    
        // Ajouter un écouteur d'événements pour le bouton close-btn_2
        var closeBtn_2 = document.getElementById('close-btn_2');
        closeBtn_2.addEventListener('click', function() {
            closeConfirmation();
        });
    
        // Fermer le bloc de confirmation
        function closeConfirmation() {
            confirmationPage.style.display = 'none';
            overlay.style.display = 'none';
        }
    }




<script>
    document.getElementById('delete-history-btn').addEventListener('click', function() {
        if (confirm('Are you sure you want to delete your transaction history? This action cannot be undone.')) {
            fetch('/delete_history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json' // Include this if you are using CSRF protection
                },
                credentials: 'include'  // Include cookies in the request
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Transaction history deleted successfully.');
                    window.location.reload();
                } else {
                    alert('An error occurred while deleting the transaction history.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while deleting the transaction history.');
            });
        }
    });
    </script>





*/

});

