export class UIManager {
    showLoading(action) {
        const actionArea = document.querySelector(`[data-action="${action}"]`);
        if (actionArea) {
            actionArea.classList.add('loading');
            const spinner = document.createElement('div');
            spinner.className = 'loading-spinner';
            actionArea.appendChild(spinner);
        }
    }

    hideLoading(action) {
        const actionArea = document.querySelector(`[data-action="${action}"]`);
        if (actionArea) {
            actionArea.classList.remove('loading');
            const spinner = actionArea.querySelector('.loading-spinner');
            if (spinner) spinner.remove();
        }
    }
}