
function redirect(element, location){
    element.addEventListener('click', ()=>{
        window.location.href = location;
    })
}

window.addEventListener('load', ()=>{
    let children = Array.from(document.getElementById("choice-container").children);
    children.forEach((element)=>{
        element.addEventListener('mouseenter', ()=>{
            element.style['background-color'] = "blue" 
            console.log("inside")

        })

        element.addEventListener('mouseleave', ()=>{
            element.style['background-color'] = 'rgb(163, 12, 12)';
  

        })

        if (element.id == "chicken"){
            let location = "page_3.html";
            redirect(element, location); 


        }
        else if (element.id == "knock"){
            let location = "page_4.html"
            redirect(element, location)

        }
        else{
            let location = "page_5.html" 
            redirect(element, location); 

        }

    })

    

})