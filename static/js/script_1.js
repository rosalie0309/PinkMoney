document.addEventListener('DOMContentLoaded', function() {
    var payementBtn = document.getElementById('payement-btn');
    var historyBtn = document.getElementById('history-btn');
    var product = document.getElementById('product');
    var paymentContainer = document.getElementById('payment-container');
    var historyContainer = document.getElementById('history-container');
    var closeBtn_1 = document.getElementById('close-btn_1');
    var closeBtn_2 = document.getElementById('close-btn_2');
    var closeBtn_11 = document.getElementById('close-btn_11');
    var closeBtn_20 = document.getElementById('close-btn_20');
    var signupAccountBtn = document.getElementById('signup-account-btn'); 
    var signupAccountFormContainer= document.getElementById('signup-account-form-container');
    var loginStartPayment = document.getElementById('login-start-payment');
    var fingerprintContainer = document.getElementById('fingerprint-verification-container')

    signupAccountBtn.addEventListener('click', function() {
        console.log('bouton de création compte cliqué');
        product.style.display = 'block';
        signupAccountFormContainer.style.display = 'block';
    })

    loginStartPayment.addEventListener('click', function() {
        product.style.display = 'block';
        paymentContainer.style.display = 'block';
        signupAccountFormContainer.style.display = 'none';
    })

    payementBtn.addEventListener('click', function() {
        console.log('Image cliquée');
        product.style.display = 'block';
        console.log('Je deviens flou');
        paymentContainer.style.display = 'block';
        console.log('Fais ton paiement');
    });

    // Afficher l'historique des différents payements des utilisateurs
    historyBtn.addEventListener('click', function() {
        product.style.display = 'block';
        historyContainer.style.display = 'block';
    });

    // Fonction pour gérer la fermeture des boutons
    function closeButtons(buttonId) {
        product.style.display = 'none';
        paymentContainer.style.display = 'none';
        signupAccountFormContainer.style.display = 'none';
        historyContainer.style.display = 'none';
        fingerprintContainer.style.display = 'none';
    }

    // Ajouter des écouteurs d'événements pour les boutons de fermeture
    closeBtn_1.addEventListener('click', function() {
        closeButtons('close-btn_1');
    });

    closeBtn_2.addEventListener('click', function() {
        closeButtons('close-btn_2');
    });

    closeBtn_11.addEventListener('click', function() {
        closeButtons('close-btn_11');
    });

    closeBtn_20.addEventListener('click', function() {
        closeButtons('close-btn_20');
    });

});

