document.addEventListener('DOMContentLoaded', () => {
    // Make sidebar collapse on click
    document.querySelector('#show-sidebar-button').onclick = () => {
        document.querySelector('#sidebar').classList.toggle('view-sidebar');
    };

    //make 'enter' enter key submit message
    let msg = document.querySelector('#user_message');
    msg.addEventListener('keyup', event => {
        event.preventDefault();
        if (event.keyCode === 13){
            document.querySelector('#send_message').click();
        }
    });
});
