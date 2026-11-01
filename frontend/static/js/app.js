
document.addEventListener("DOMContentLoaded", () => {
  // Preserve dataset file selection.
  const input = document.getElementById("dataset");
  const selected = document.getElementById("selected-file");

  if (input && selected) {
    input.addEventListener("change", () => {
      selected.textContent =
        input.files && input.files.length
          ? input.files[0].name
          : "No file selected";
    });
  }

  // Read model results embedded by the Flask HTML template.
  const dataElement = document.getElementById("model-comparison-data");
  const performanceCanvas = document.getElementById("modelPerformanceChart");

  if (!dataElement || !performanceCanvas || typeof Chart === "undefined") {
    return;
  }

  let models;

  try {
    models = JSON.parse(dataElement.textContent);
  } catch (error) {
    console.error("Could not parse model comparison data:", error);
    return;
  }

  if (!Array.isArray(models) || models.length === 0) {
    console.warn("No model comparison results are available.");
    return;
  }

  const validModels = models.filter(
    (model) =>
      model &&
      typeof model.model === "string" &&
      Number.isFinite(model.accuracy) &&
      Number.isFinite(model.precision_attack) &&
      Number.isFinite(model.recall_attack) &&
      Number.isFinite(model.f1_attack)
  );

  if (validModels.length === 0) {
    console.warn("No valid model metrics were found.");
    return;
  }

  const labels = validModels.map((model) => model.model);
  const percent = (values) => values.map((value) => value * 100);

  const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: "#302830"
        }
      }
    },
    scales: {
      x: {
        ticks: { color: "#302830" },
        grid: { display: false }
      },
      y: {
        beginAtZero: true,
        ticks: { color: "#302830" },
        grid: { color: "rgba(73, 38, 63, 0.12)" }
      }
    }
  };

  new Chart(performanceCanvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Accuracy (%)",
          data: percent(validModels.map((model) => model.accuracy))
        },
        {
          label: "Precision (%)",
          data: percent(validModels.map((model) => model.precision_attack))
        },
        {
          label: "Recall (%)",
          data: percent(validModels.map((model) => model.recall_attack))
        },
        {
          label: "F1-score (%)",
          data: percent(validModels.map((model) => model.f1_attack))
        }
      ]
    },
    options: {
      ...commonOptions,
      scales: {
        ...commonOptions.scales,
        y: {
          ...commonOptions.scales.y,
          max: 100,
          title: { display: true, text: "Score (%)" }
        }
      }
    }
  });

  const falsePositiveCanvas = document.getElementById("falsePositiveChart");

  if (falsePositiveCanvas) {
    new Chart(falsePositiveCanvas, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "False Positive Rate (%)",
          data: percent(validModels.map((model) => model.false_positive_rate))
        }]
      },
      options: {
        ...commonOptions,
        scales: {
          ...commonOptions.scales,
          y: {
            ...commonOptions.scales.y,
            title: { display: true, text: "Rate (%)" }
          }
        }
      }
    });
  }

  const executionCanvas = document.getElementById("executionTimeChart");

  if (executionCanvas) {
    new Chart(executionCanvas, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Training (seconds)",
            data: validModels.map((model) => model.training_seconds)
          },
          {
            label: "Prediction (seconds)",
            data: validModels.map((model) => model.prediction_seconds)
          }
        ]
      },
      options: {
        ...commonOptions,
        scales: {
          ...commonOptions.scales,
          y: {
            ...commonOptions.scales.y,
            title: { display: true, text: "Seconds" }
          }
        }
      }
    });
  }

  const bestModel = [...validModels].sort(
    (a, b) => b.f1_attack - a.f1_attack
  )[0];

  const confusionCanvas = document.getElementById("confusionMatrixChart");

  if (confusionCanvas && bestModel) {
    new Chart(confusionCanvas, {
      type: "bar",
      data: {
        labels: ["Actual Normal", "Actual Attack"],
        datasets: [
          {
            label: "Correct classifications",
            data: [bestModel.true_negative, bestModel.true_positive]
          },
          {
            label: "Incorrect classifications",
            data: [bestModel.false_positive, bestModel.false_negative]
          }
        ]
      },
      options: {
        ...commonOptions,
        scales: {
          ...commonOptions.scales,
          y: {
            ...commonOptions.scales.y,
            title: { display: true, text: "Number of rows" }
          }
        },
        plugins: {
          ...commonOptions.plugins,
          title: {
            display: true,
            text: `Best F1 model: ${bestModel.model}`
          }
        }
      }
    });
  }
});

