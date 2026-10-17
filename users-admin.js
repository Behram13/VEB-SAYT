const tableBody = document.getElementById("usersTableBody");
const userCount = document.getElementById("userCount");
const verifyModal = document.getElementById("passwordVerifyModal");
const closeVerifyModal = document.getElementById("closeVerifyModal");
const verifyFin = document.getElementById("verifyFin");
const verifyPassword = document.getElementById("verifyPassword");
const verifyPasswordButton = document.getElementById("verifyPasswordButton");
const verifyResult = document.getElementById("verifyResult");

let selectedUserId = null;

async function loadUsers() {
    try {
        const response = await fetch("/users");
        const data = await response.json();

        tableBody.innerHTML = "";

        if (!response.ok) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6">İstifadəçiləri yükləmək mümkün olmadı.</td>
                </tr>
            `;
            userCount.innerText = "0";
            return;
        }

        userCount.innerText = data.length;

        if (data.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6">Hazırda qeydiyyatdan keçmiş istifadəçi yoxdur.</td>
                </tr>
            `;
            return;
        }

        data.forEach(function (user) {
            let status = "Aktiv";
            let statusClass = "status-active";

            if (user.locked_until) {
                const lockedUntil = new Date(user.locked_until);
                const now = new Date();

                if (lockedUntil > now) {
                    status = "Bloklanıb";
                    statusClass = "status-locked";
                }
            }

            let createdAt = "-";

            if (user.created_at) {
                createdAt = new Date(user.created_at).toLocaleString("az-AZ");
            }

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${user.id}</td>
                <td>${escapeHtml(user.fin)}</td>
                <td>
                    <button
                        class="password-check-button"
                        data-user-id="${user.id}"
                        data-fin="${escapeHtml(user.fin)}"
                        type="button"
                    >
                        Parolu yoxla
                    </button>
                </td>
                <td class="hash-cell">${escapeHtml(user.password_hash)}</td>
                <td>${createdAt}</td>
                <td class="${statusClass}">${status}</td>
            `;

            tableBody.appendChild(row);
        });

        addPasswordButtonEvents();

    } catch (error) {
        console.error("Users panel xətası:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="6">Serverlə əlaqə yaratmaq mümkün olmadı.</td>
            </tr>
        `;

        userCount.innerText = "0";
    }
}

function addPasswordButtonEvents() {
    const buttons = document.querySelectorAll(".password-check-button");

    buttons.forEach(function (button) {
        button.addEventListener("click", function () {
            selectedUserId = button.dataset.userId;
            verifyFin.innerText = button.dataset.fin;
            verifyPassword.value = "";
            verifyResult.innerText = "";
            verifyModal.classList.add("show");

            setTimeout(function () {
                verifyPassword.focus();
            }, 100);
        });
    });
}

verifyPasswordButton.addEventListener("click", async function () {
    const password = verifyPassword.value;

    verifyResult.innerText = "";

    if (!selectedUserId) {
        verifyResult.style.color = "red";
        verifyResult.innerText = "İstifadəçi seçilməyib.";
        return;
    }

    if (!password) {
        verifyResult.style.color = "red";
        verifyResult.innerText = "Parolu daxil edin.";
        return;
    }

    verifyPasswordButton.disabled = true;
    verifyPasswordButton.innerText = "Yoxlanılır...";

    try {
        const response = await fetch(
            "/users/" + selectedUserId + "/verify-password",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    password: password
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            verifyResult.style.color = "red";
            verifyResult.innerText =
                data.error ||
                "Parolu yoxlamaq mümkün olmadı.";
            return;
        }

        if (data.matches) {
            verifyResult.style.color = "green";
            verifyResult.innerText =
                "✓ Parol bu istifadəçinin hash-i ilə uyğundur.";
        } else {
            verifyResult.style.color = "red";
            verifyResult.innerText =
                "✗ Parol bu istifadəçinin hash-i ilə uyğun deyil.";
        }

    } catch (error) {
        console.error("Password verify xətası:", error);

        verifyResult.style.color = "red";
        verifyResult.innerText =
            "Serverlə əlaqə yaratmaq mümkün olmadı.";

    } finally {
        verifyPasswordButton.disabled = false;
        verifyPasswordButton.innerText = "Yoxla";
    }
});

verifyPassword.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        event.preventDefault();
        verifyPasswordButton.click();
    }
});

closeVerifyModal.addEventListener("click", function () {
    closePasswordModal();
});

verifyModal.addEventListener("click", function (event) {
    if (event.target === verifyModal) {
        closePasswordModal();
    }
});

document.addEventListener("keydown", function (event) {
    if (
        event.key === "Escape" &&
        verifyModal.classList.contains("show")
    ) {
        closePasswordModal();
    }
});

function closePasswordModal() {
    verifyModal.classList.remove("show");
    verifyPassword.value = "";
    verifyResult.innerText = "";
    selectedUserId = null;
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
}

loadUsers();