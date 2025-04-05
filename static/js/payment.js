document.addEventListener('DOMContentLoaded', function () {
    var paymentForm = document.getElementById('payment-form');
    var paymentFormContainer = document.getElementById('payment-container');
    var fingerprintContainer = document.getElementById('fingerprint-verification-container');
    var fingerprintForm = document.getElementById('fingerprint');
    var nextBtn = document.getElementById('next-btn');
    var fingerprintImage = document.getElementById('fingerprint-image');
    var fingerprintFormElement = document.getElementById('fingerprint-form');
    var btnBuy = document.getElementById('buy-btn');

    nextBtn.addEventListener('click', function(event) {
        paymentForm.style.display = 'none';
        paymentFormContainer.style.display = 'none';
        fingerprintContainer.style.display = 'flex';
        fingerprintForm.style.display = 'flex';
        btnBuy.style.display = 'block';
    });

    fingerprintFormElement.addEventListener('submit', function(event) {
        var formData = new FormData(paymentForm);
        var fingerprintData = new FormData(fingerprintFormElement);
        for (var pair of fingerprintData.entries()) {
            formData.append(pair[0], pair[1]);
        }

        fetch(paymentUrl, {
            method: 'POST',
            body: formData
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(function(data) {
            console.log(data);
            fingerprintContainer.style.display = 'none';
            if (data.status === 'success') {
                window.location.href = '/payment?success=true';
            } else {
                window.location.href = '/payment?error=true&message=' + encodeURIComponent(data.message);
            }
        })
        .catch(function(error) {
            console.error('There was a problem with your fetch operation:', error);
            fingerprintContainer.style.display = 'none';
            window.location.href = '/payment?error=true&message=' + encodeURIComponent('There was an error processing your request. Please try again.');
        });

        event.preventDefault();
    });

    function startRealTimeFingerprintRecognition() {
        alert("Starting real-time fingerprint recognition...");
    }
});
