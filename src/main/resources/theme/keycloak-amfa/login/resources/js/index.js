document.onreadystatechange = () => {
    if (document.readyState === 'complete' && document.getElementById("screenRes")) {
        const width = window.screen.width;
        const height = window.screen.height;
        document.getElementById("screenRes").value = `${width}x${height}`;
        const screenResForm = document.getElementById("screenResForm");
        if (screenResForm) {
            screenResForm.submit();
        }
    }
}
