const tableBody = document.getElementById("appointmentsTableBody");
const appointmentCount = document.getElementById("appointmentCount");
const deleteModal = document.getElementById("deleteModal");
const cancelDeleteButton = document.getElementById("cancelDeleteButton");
const confirmDeleteButton = document.getElementById("confirmDeleteButton");

let selectedAppointmentId = null;

async function loadAppointments() {
    try {
        const response = await fetch("/appointments");
        const data = await response.json();

        if (!response.ok) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="8">Növbələri yükləmək mümkün olmadı.</td>
                </tr>
            `;
            appointmentCount.innerText = "0";
            return;
        }

        appointmentCount.innerText = data.length;
        tableBody.innerHTML = "";

        if (data.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="8">Hazırda qeydə alınmış növbə yoxdur.</td>
                </tr>
            `;
            return;
        }

        data.forEach(function (appointment) {
            const row = document.createElement("tr");

            const tarix = appointment.tarix
                ? new Date(appointment.tarix).toLocaleDateString("az-AZ")
                : "-";

            let saat = appointment.saat || "-";

            if (saat && saat.length >= 5) {
                saat = saat.substring(0, 5);
            }

            row.innerHTML = `
                <td>${appointment.id}</td>
                <td>${escapeHtml(appointment.ad)}</td>
                <td>${escapeHtml(appointment.soyad)}</td>
                <td>${escapeHtml(appointment.telefon)}</td>
                <td>${escapeHtml(appointment.hekim)}</td>
                <td>${tarix}</td>
                <td>${escapeHtml(saat)}</td>
                <td>
                    <button
                        class="delete-button"
                        data-id="${appointment.id}"
                        type="button"
                    >
                        Sil
                    </button>
                </td>
            `;

            tableBody.appendChild(row);
        });

        addDeleteButtonEvents();

    } catch (error) {
        console.error("Appointments load xətası:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="8">Serverlə əlaqə yaratmaq mümkün olmadı.</td>
            </tr>
        `;

        appointmentCount.innerText = "0";
    }
}

function addDeleteButtonEvents() {
    const buttons = document.querySelectorAll(".delete-button");

    buttons.forEach(function (button) {
        button.addEventListener("click", function () {
            selectedAppointmentId = button.dataset.id;
            openDeleteModal();
        });
    });
}

function openDeleteModal() {
    deleteModal.classList.add("show");
}

function closeDeleteModal() {
    deleteModal.classList.remove("show");
    selectedAppointmentId = null;
}

cancelDeleteButton.addEventListener("click", function () {
    closeDeleteModal();
});

deleteModal.addEventListener("click", function (event) {
    if (event.target === deleteModal) {
        closeDeleteModal();
    }
});

document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && deleteModal.classList.contains("show")) {
        closeDeleteModal();
    }
});

confirmDeleteButton.addEventListener("click", async function () {
    if (!selectedAppointmentId) {
        return;
    }

    confirmDeleteButton.disabled = true;
    confirmDeleteButton.innerText = "Silinir...";

    try {
        const response = await fetch(
            "/appointments/" + selectedAppointmentId,
            {
                method: "DELETE"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "Növbəni silmək mümkün olmadı.");
            return;
        }

        closeDeleteModal();
        await loadAppointments();

    } catch (error) {
        console.error("Delete xətası:", error);
        alert("Serverlə əlaqə yaratmaq mümkün olmadı.");

    } finally {
        confirmDeleteButton.disabled = false;
        confirmDeleteButton.innerText = "Sil";
    }
});

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
}

loadAppointments();