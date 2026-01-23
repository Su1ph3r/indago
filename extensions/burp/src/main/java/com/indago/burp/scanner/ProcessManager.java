package com.indago.burp.scanner;

import burp.api.montoya.logging.Logging;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Manages external process lifecycle for Indago execution.
 */
public class ProcessManager {

    private final Logging logging;
    private Process process;
    private Thread outputReader;
    private Thread errorReader;
    private volatile boolean running = false;

    public ProcessManager(Logging logging) {
        this.logging = logging;
    }

    /**
     * Start a process with the given command and working directory.
     *
     * @param command       The command to execute as a list of arguments
     * @param workingDir    The working directory (can be null)
     * @param outputHandler Callback for stdout lines
     * @param errorHandler  Callback for stderr lines
     * @return true if the process started successfully
     */
    public boolean start(List<String> command, File workingDir,
                         Consumer<String> outputHandler, Consumer<String> errorHandler) {
        if (running) {
            logging.logToError("Process already running");
            return false;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            if (workingDir != null && workingDir.isDirectory()) {
                pb.directory(workingDir);
            }

            // Merge environment - inherit current environment
            pb.environment().putAll(System.getenv());

            logging.logToOutput("Starting process: " + String.join(" ", command));
            process = pb.start();
            running = true;

            // Start output reader thread
            outputReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (outputHandler != null) {
                            outputHandler.accept(line);
                        }
                    }
                } catch (IOException e) {
                    if (running) {
                        logging.logToError("Error reading process output: " + e.getMessage());
                    }
                }
            }, "Indago-stdout");
            outputReader.setDaemon(true);
            outputReader.start();

            // Start error reader thread
            errorReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (errorHandler != null) {
                            errorHandler.accept(line);
                        }
                    }
                } catch (IOException e) {
                    if (running) {
                        logging.logToError("Error reading process stderr: " + e.getMessage());
                    }
                }
            }, "Indago-stderr");
            errorReader.setDaemon(true);
            errorReader.start();

            return true;

        } catch (IOException e) {
            logging.logToError("Failed to start process: " + e.getMessage());
            running = false;
            return false;
        }
    }

    /**
     * Stop the running process.
     */
    public void stop() {
        if (!running || process == null) {
            return;
        }

        running = false;
        logging.logToOutput("Stopping process...");

        try {
            // Try graceful termination first
            process.destroy();

            // Wait for up to 5 seconds
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                // Force kill if still running
                logging.logToOutput("Process did not terminate gracefully, forcing...");
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }

            logging.logToOutput("Process stopped");

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }

        // Interrupt reader threads
        if (outputReader != null) {
            outputReader.interrupt();
        }
        if (errorReader != null) {
            errorReader.interrupt();
        }
    }

    /**
     * Check if the process is currently running.
     */
    public boolean isRunning() {
        return running && process != null && process.isAlive();
    }

    /**
     * Wait for the process to complete.
     *
     * @param timeout Maximum time to wait
     * @param unit    Time unit
     * @return Exit code, or -1 if timeout or error
     */
    public int waitFor(long timeout, TimeUnit unit) {
        if (process == null) {
            return -1;
        }

        try {
            if (process.waitFor(timeout, unit)) {
                running = false;
                return process.exitValue();
            }
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    /**
     * Wait for the process to complete with no timeout.
     *
     * @return Exit code, or -1 on error
     */
    public int waitFor() {
        if (process == null) {
            return -1;
        }

        try {
            int exitCode = process.waitFor();
            running = false;
            return exitCode;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    /**
     * Get the exit code if the process has completed.
     *
     * @return Exit code, or -1 if still running or not started
     */
    public int getExitCode() {
        if (process == null || process.isAlive()) {
            return -1;
        }
        return process.exitValue();
    }
}
