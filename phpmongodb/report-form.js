const btn_showsqli = document.getElementById("sqli_show");
const view_des = document.getElementById("description-sql");

btn_showsqli.addEventListener("click", () => {
  view_des.style.display = "block";
  console.log(1);
});

const btn_showxss = document.getElementById("xss_show");
const view_desxss = document.getElementById("description-xss");

btn_showxss.addEventListener("click", () => {
  view_desxss.style.display = "block";
  console.log(1);
});
