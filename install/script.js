const totalSteps = 4;

function updateProgressBar(stepNumber) {
    const progressBar = document.getElementById('progressBar');

    if (!progressBar) return;

    const percentage = (stepNumber / totalSteps) * 100;

    progressBar.style.width = percentage + '%';
    progressBar.setAttribute('aria-valuenow', percentage);
    progressBar.textContent = 'Step ' + stepNumber + ' of ' + totalSteps;

    if (stepNumber === totalSteps) {
        setTimeout(() => {
            window.location.href = '../login.php';
        }, 2000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);

    const step = urlParams.get('step')
        ? parseInt(urlParams.get('step'), 10)
        : 1;

    updateProgressBar(step);
});