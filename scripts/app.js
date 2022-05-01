let health = 100;

window.addEventListener('load', () => {
    title_btn = document.getElementsByClassName('Title-Btn')[0];
    green_bar = document.getElementsByClassName('Green-Bar')[0]; 
    health_text = document.getElementsByClassName('Health-Text')[0];
    tutorial_person = document.getElementById("tutorial") 
    tutorial_text = document.getElementById("tutorial-text")
    
    debounce = true; 

    title_btn.addEventListener('click', () => {
        if (debounce){
            debounce = false; 

            counter = 0; 

            myInterval = setInterval(()=>{
                if (counter == 19){
                    debounce = true; 
                    clearInterval(myInterval)
                }
                health = health - 1; 
                green_bar.style.width = health+"%"
                health_text.innerHTML = health + " / 100"

                counter++; 

                if (health == 0){
                    let timer_counter = 0; 

                    timer = setInterval(()=>{
                        timer_counter++;
                        if (timer_counter == 5){
                            clearInterval(timer); 
                            title_btn.style.backgroundColor = "Green"; 
                            title_btn.innerHTML = "Continue";  
                        }
                    }, 1000) 

                    tutorial_person.style.opacity = 1; 
                    tutorial_text.style.opacity = 1; 
                                  

                    const app = document.getElementById("tutorial-text")

                    let typewriter = new Typewriter(app, {
                        strings: [
                        "You did so GOOOD",
                        "You're so amazing!!!", 
                        "You totally 'Killed' it",
                        ], 
                        autoStart: true,
                        loop: true, 
                        delay: 60,
                        pauseFor: 1000,

                    })
                }
            }, 50)

            
            if (health <= 0){
                window.location.href = "page_1.html"
            }
        }
    })
})
