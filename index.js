import express from "express";

const app = express();
const port = 3000;

app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static("public"));

app.get("/",(req,res) => {
    res.render("index.ejs");
});

app.get("/logincard_student",(req,res) => {
    res.render("studentLogin.ejs");
});

app.get("/logincard_teacher",(req,res) => {
    res.render("teacherLogin.ejs");
});



app.listen(`${port}`, () => {
    console.log("server running on port 3000");
});