const sign=document.querySelector('.sign');
const login=document.querySelector('.login');
login.addEventListener('click',()=>{
    sign.classList.add('popup');
});
const close=document.querySelector('.icon-close');
close.addEventListener('click',()=>{
    sign.classList.remove('popup');
});