const authModal = document.getElementById("authModal");
const closeAuthModal = document.getElementById("closeAuthModal");
const loginTabButton = document.getElementById("loginTabButton");
const registerTabButton = document.getElementById("registerTabButton");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const loginMessage = document.getElementById("loginMessage");
const registerMessage = document.getElementById("registerMessage");
const guestMenu = document.getElementById("guestMenu");
const userMenu = document.getElementById("userMenu");
const userFin = document.getElementById("userFin");
const logoutButton = document.getElementById("logoutButton");
const appointmentForm = document.getElementById("novbe-formu");
const appointmentNotice = document.getElementById("appointmentLoginNotice");
const navNovbe = document.getElementById("navNovbe");
const heroAppointmentButton = document.getElementById("heroAppointmentButton");
const changePasswordButton = document.getElementById("changePasswordButton");
const changePasswordModal = document.getElementById("changePasswordModal");
const closeChangePasswordModal = document.getElementById("closeChangePasswordModal");
const changePasswordForm = document.getElementById("changePasswordForm");
const changePasswordMessage = document.getElementById("changePasswordMessage");

let loggedIn = false;

function parolGucludur(password) {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s]).{8,64}$/;
    return regex.test(password);
}

function resetPasswordVisibility(container) {
    const inputs = container.querySelectorAll(".password-field input");
    const buttons = container.querySelectorAll(".password-toggle");

    inputs.forEach(function (input) {
        input.type = "password";
    });

    buttons.forEach(function (button) {
        button.textContent = "👁";
        button.setAttribute("aria-label", "Parolu göstər");
    });
}

document.querySelectorAll(".password-toggle").forEach(function (button) {
    button.addEventListener("click", function () {
        const targetId = button.dataset.target;
        const input = document.getElementById(targetId);

        if (!input) {
            return;
        }

        if (input.type === "password") {
            input.type = "text";
            button.textContent = "🙈";
            button.setAttribute("aria-label", "Parolu gizlət");
        } else {
            input.type = "password";
            button.textContent = "👁";
            button.setAttribute("aria-label", "Parolu göstər");
        }

        input.focus();
    });
});

function openAuthModal(tab) {
    authModal.classList.add("show");
    document.body.classList.add("modal-open");
    resetPasswordVisibility(authModal);

    if (tab === "register") {
        showRegisterTab();
    } else {
        showLoginTab();
    }
}

function closeModal() {
    authModal.classList.remove("show");
    document.body.classList.remove("modal-open");
    loginMessage.innerText = "";
    registerMessage.innerText = "";
    resetPasswordVisibility(authModal);
}

function showLoginTab() {
    loginTabButton.classList.add("active");
    registerTabButton.classList.remove("active");
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
    loginMessage.innerText = "";
    registerMessage.innerText = "";
    resetPasswordVisibility(authModal);
}

function showRegisterTab() {
    registerTabButton.classList.add("active");
    loginTabButton.classList.remove("active");
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
    loginMessage.innerText = "";
    registerMessage.innerText = "";
    resetPasswordVisibility(authModal);
}

document.getElementById("openLoginButton").addEventListener("click", function () {
    openAuthModal("login");
});

document.getElementById("openRegisterButton").addEventListener("click", function () {
    openAuthModal("register");
});

document.getElementById("noticeLoginButton").addEventListener("click", function () {
    openAuthModal("login");
});

document.getElementById("noticeRegisterButton").addEventListener("click", function () {
    openAuthModal("register");
});

closeAuthModal.addEventListener("click", closeModal);

authModal.addEventListener("click", function (event) {
    if (event.target === authModal) {
        closeModal();
    }
});

loginTabButton.addEventListener("click", showLoginTab);
registerTabButton.addEventListener("click", showRegisterTab);

document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
        if (authModal.classList.contains("show")) {
            closeModal();
        }

        if (changePasswordModal.classList.contains("show")) {
            closeChangePasswordModalFunction();
        }
    }
});

registerForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const fin = document.getElementById("registerFin").value.trim().toUpperCase();
    const password = document.getElementById("registerPassword").value;
    const passwordRepeat = document.getElementById("registerPasswordRepeat").value;

    registerMessage.innerText = "";

    if (!/^[A-Z0-9]{7}$/.test(fin)) {
        registerMessage.style.color = "red";
        registerMessage.innerText = "FİN kod 7 hərf və rəqəmdən ibarət olmalıdır.";
        return;
    }

    if (!parolGucludur(password)) {
        registerMessage.style.color = "red";
        registerMessage.innerText = "Parol minimum 8 simvol olmalı, böyük hərf, kiçik hərf, rəqəm və xüsusi simvol içərməlidir.";
        return;
    }

    if (password !== passwordRepeat) {
        registerMessage.style.color = "red";
        registerMessage.innerText = "Parollar eyni deyil.";
        return;
    }

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                fin: fin,
                password: password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            registerMessage.style.color = "red";
            registerMessage.innerText = data.error || "Qeydiyyat mümkün olmadı.";
            return;
        }

        registerMessage.style.color = "green";
        registerMessage.innerText = "Qeydiyyat uğurludur. İndi giriş edin.";
        registerForm.reset();
        resetPasswordVisibility(authModal);

        setTimeout(function () {
            showLoginTab();
            document.getElementById("loginFin").value = fin;
        }, 800);

    } catch (error) {
        console.error("Register xətası:", error);
        registerMessage.style.color = "red";
        registerMessage.innerText = "Serverlə əlaqə yaratmaq mümkün olmadı.";
    }
});

loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const fin = document.getElementById("loginFin").value.trim().toUpperCase();
    const password = document.getElementById("loginPassword").value;

    loginMessage.innerText = "";

    if (!fin || !password) {
        loginMessage.style.color = "red";
        loginMessage.innerText = "FİN və parolu daxil edin.";
        return;
    }

    if (!/^[A-Z0-9]{7}$/.test(fin)) {
        loginMessage.style.color = "red";
        loginMessage.innerText = "FİN kod 7 simvoldan ibarət olmalıdır.";
        return;
    }

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                fin: fin,
                password: password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            loginMessage.style.color = "red";
            loginMessage.innerText = data.error || "Giriş mümkün olmadı.";
            return;
        }

        loginMessage.style.color = "green";
        loginMessage.innerText = "Giriş uğurludur.";
        loginForm.reset();
        resetPasswordVisibility(authModal);

        await checkLoginStatus();

        setTimeout(function () {
            closeModal();
            scrollToAppointment();
        }, 600);

    } catch (error) {
        console.error("Login xətası:", error);
        loginMessage.style.color = "red";
        loginMessage.innerText = "Serverlə əlaqə yaratmaq mümkün olmadı.";
    }
});

async function checkLoginStatus() {
    try {
        const response = await fetch("/me");

        if (!response.ok) {
            setLoggedOutState();
            return;
        }

        const data = await response.json();

        if (data.loggedIn) {
            setLoggedInState(data.fin);
        } else {
            setLoggedOutState();
        }

    } catch (error) {
        console.error("Login status xətası:", error);
        setLoggedOutState();
    }
}

function setLoggedInState(fin) {
    loggedIn = true;
    guestMenu.classList.add("hidden");
    userMenu.classList.remove("hidden");
    userFin.innerText = "FİN: " + fin;
    appointmentNotice.classList.add("hidden");
    appointmentForm.classList.remove("locked");
    setAppointmentFieldsDisabled(false);
}

function setLoggedOutState() {
    loggedIn = false;
    guestMenu.classList.remove("hidden");
    userMenu.classList.add("hidden");
    userFin.innerText = "";
    appointmentNotice.classList.remove("hidden");
    appointmentForm.classList.add("locked");
    setAppointmentFieldsDisabled(true);
}

function setAppointmentFieldsDisabled(disabled) {
    const elements = appointmentForm.querySelectorAll("input, select, button");

    elements.forEach(function (element) {
        element.disabled = disabled;
    });
}

changePasswordButton.addEventListener("click", function () {
    changePasswordForm.reset();
    changePasswordMessage.innerText = "";
    resetPasswordVisibility(changePasswordModal);
    changePasswordModal.classList.add("show");
    document.body.classList.add("modal-open");
});

closeChangePasswordModal.addEventListener("click", function () {
    closeChangePasswordModalFunction();
});

changePasswordModal.addEventListener("click", function (event) {
    if (event.target === changePasswordModal) {
        closeChangePasswordModalFunction();
    }
});

function closeChangePasswordModalFunction() {
    changePasswordModal.classList.remove("show");
    document.body.classList.remove("modal-open");
    changePasswordForm.reset();
    changePasswordMessage.innerText = "";
    resetPasswordVisibility(changePasswordModal);
}

changePasswordForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const newPasswordRepeat = document.getElementById("newPasswordRepeat").value;

    changePasswordMessage.innerText = "";

    if (!currentPassword || !newPassword || !newPasswordRepeat) {
        changePasswordMessage.style.color = "red";
        changePasswordMessage.innerText = "Bütün parol xanalarını doldurun.";
        return;
    }

    if (!parolGucludur(newPassword)) {
        changePasswordMessage.style.color = "red";
        changePasswordMessage.innerText = "Yeni parol minimum 8 simvol olmalı, böyük hərf, kiçik hərf, rəqəm və xüsusi simvol içərməlidir.";
        return;
    }

    if (newPassword !== newPasswordRepeat) {
        changePasswordMessage.style.color = "red";
        changePasswordMessage.innerText = "Yeni parollar eyni deyil.";
        return;
    }

    if (currentPassword === newPassword) {
        changePasswordMessage.style.color = "red";
        changePasswordMessage.innerText = "Yeni parol cari parolla eyni ola bilməz.";
        return;
    }

    try {
        const response = await fetch("/change-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                currentPassword: currentPassword,
                newPassword: newPassword
            })
        });

        const data = await response.json();

        if (!response.ok) {
            changePasswordMessage.style.color = "red";
            changePasswordMessage.innerText = data.error || "Parolu dəyişmək mümkün olmadı.";
            return;
        }

        changePasswordMessage.style.color = "green";
        changePasswordMessage.innerText = "Parol uğurla dəyişdirildi.";
        changePasswordForm.reset();
        resetPasswordVisibility(changePasswordModal);

        setTimeout(function () {
            closeChangePasswordModalFunction();
        }, 1000);

    } catch (error) {
        console.error("Parol dəyişmə xətası:", error);
        changePasswordMessage.style.color = "red";
        changePasswordMessage.innerText = "Serverlə əlaqə yaratmaq mümkün olmadı.";
    }
});

logoutButton.addEventListener("click", async function () {
    try {
        const response = await fetch("/logout", {
            method: "POST"
        });

        if (!response.ok) {
            alert("Çıxış zamanı xəta baş verdi.");
            return;
        }

        setLoggedOutState();

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });

    } catch (error) {
        console.error("Logout xətası:", error);
        alert("Serverlə əlaqə yaratmaq mümkün olmadı.");
    }
});

function scrollToAppointment() {
    document.getElementById("novbe").scrollIntoView({
        behavior: "smooth"
    });
}

navNovbe.addEventListener("click", function (event) {
    event.preventDefault();

    if (!loggedIn) {
        openAuthModal("login");
        return;
    }

    scrollToAppointment();
});

heroAppointmentButton.addEventListener("click", function () {
    if (!loggedIn) {
        openAuthModal("login");
        return;
    }

    scrollToAppointment();
});

appointmentForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const mesaj = document.getElementById("mesaj");

    if (!loggedIn) {
        openAuthModal("login");
        return;
    }

    const ad = document.getElementById("ad").value.trim();
    const soyad = document.getElementById("soyad").value.trim();
    const telefon = document.getElementById("telefon").value.trim();
    const hekim = document.getElementById("hekim").value;
    const tarix = document.getElementById("tarix").value;
    const saat = document.getElementById("saat").value;

    if (!ad || !soyad || !telefon || !hekim || !tarix || !saat) {
        mesaj.style.color = "red";
        mesaj.innerText = "Xahiş edirik, bütün xanaları doldurun.";
        return;
    }

    try {
        const response = await fetch("/novbe", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ad: ad,
                soyad: soyad,
                telefon: telefon,
                hekim: hekim,
                tarix: tarix,
                saat: saat
            })
        });

        const data = await response.json();

        if (response.status === 401) {
            setLoggedOutState();
            openAuthModal("login");
            return;
        }

        if (!response.ok) {
            mesaj.style.color = "red";
            mesaj.innerText = data.error || "Növbə yaradılmadı.";
            return;
        }

        mesaj.style.color = "green";
        mesaj.innerText = data.message || "Növbəniz uğurla qeydə alındı.";
        appointmentForm.reset();

    } catch (error) {
        console.error("Növbə xətası:", error);
        mesaj.style.color = "red";
        mesaj.innerText = "Serverlə əlaqə yaratmaq mümkün olmadı.";
    }
});

checkLoginStatus();