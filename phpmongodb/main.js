const btn_scan = document.getElementById("scanner");
const btn_history = document.getElementById("scan-history");
const view_scan = document.getElementById("form-scanner");
const view_history = document.getElementById("form-history");
btn_scan.addEventListener("click", () => {
  view_scan.style.display = "flex";

  view_history.style.display = "none";

  btn_scan.style.fontWeight = 700;
  btn_history.style.fontWeight = 100;
});
btn_history.addEventListener("click", () => {
  view_history.style.display = "block";
  view_scan.style.display = "none";

  btn_history.style.fontWeight = 700;
  btn_scan.style.fontWeight = 100;
});

function signup(e) {
  event.preventDefault();
  var email = document.getElementById("email_username").value;
  var password = document.getElementById("password").value;
  var user = {
    email: email,
    password: password,
  };
  var json = JSON.stringify(user);
  localStorage.setItem("email", json);
  alert("Dang ky thanh cong");
}
function login(e) {
  event.preventDefault();
  var email = document.getElementById("email_username").value;
  var password = document.getElementById("password").value;
  var user = localStorage.getItem(email);
  var data = JSON.parse(user);
  if (user == null) {
    alert("Vui long dang nhap email password");
  } else if (email == data.email && password == data.password) {
    alert("Dang Nhap Thanh Cong");
    window.location.href = "todolist.html";
  } else {
    alert("Vui long dang nhap lai");
  }
}
