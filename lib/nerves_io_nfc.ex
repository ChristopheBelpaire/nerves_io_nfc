defmodule Nerves.IO.NFC do

  @moduledoc """
  Worker module that spawns the NFC poller port process and handles all communication.
  """
  @timeout 5_000_000_000

  use GenServer

  require Logger

  def start_link(callback) do
    GenServer.start_link(__MODULE__, [callback], name: __MODULE__)
  end


  defmodule State do
    @moduledoc false
    defstruct port: nil, callback: nil, last_ping: nil
  end

  def init([callback]) do
    Logger.info "NFC worker starting"
    Process.send_after(self(), {:ping, self}, 1_000)
    state = %State{callback: callback}
    {:ok, state, 0}
  end

  def handle_info({:ping, from}, state) do
    state = restart_if_timeout(state)
    Process.send_after(self(), {:ping, from}, 1_000)
    {:noreply, state}
  end

  def handle_info({port, {:data, data}}, state) do
    cmd = :erlang.binary_to_term(data)
    state = handle_cmd(cmd, state)
    {:noreply, state}
  end

  def handle_info({port, {:exit_status, 1}}, state = %State{port: port}) do
    {:stop, {:error, :port_failure}, %State{state | port: nil}}
  end

  def handle_info({port, {:exit_status, s}}, state = %State{port: port}) when s == 99 do
    IO.inspect "restart, : #{inspect s}"
    {:noreply, %State{state | port: nil}, 0}
  end

  def handle_info({port, {:exit_status, s}}, state = %State{port: port}) when s > 1 do
    # restart after 2 sec
    IO.inspect "s: #{inspect s}"
    {:noreply, %State{state | port: nil}, 2000}
  end



  def handle_info(:timeout, state = %State{port: nil}) do
    :timer.sleep 5000
    {:noreply, restart(state)}
  end

  def handle_info(unknown, state) do
    Logger.info "Huh? #{inspect unknown}"
    {:noreply, state}
  end

  def handle_info(unknown, state) do
    Logger.info "Huh? #{inspect unknown}"
    {:noreply, state}
  end


  defp restart(state) do
    executable = :code.priv_dir(:nerves_io_nfc) ++ '/nfc_poller'
    port = Port.open({:spawn_executable, executable},
                     [{:args, []},
                      {:packet, 2},
                      :use_stdio,
                      :binary,
                      :exit_status])

    %State{state | port: port}
  end

  def restart_if_timeout(state = %{last_ping: last_ping}) do
    if (last_ping  && (:erlang.system_time - last_ping > @timeout)) do
      IO.puts "restart"
      state = restart(state)
      %{state | last_ping: :erlang.system_time}
    else
      state
    end
  end

  defp handle_cmd({:ping}, state) do
    %{state | last_ping: :erlang.system_time}
  end

  defp handle_cmd({:tag, tag}, state = %State{callback: callback}) when is_function(callback) do
    callback.(tag)
    state
  end

  defp handle_cmd({:tag, tag}, state = %State{callback: {m, f}}) do
    apply(m, f, [tag])
    state
  end

  defp handle_cmd({:tag, id, ndef}, state = %State{callback: callback}) when is_function(callback) do
    callback.(id, ndef)
    state
  end

  defp handle_cmd({:tag, id, ndef }, state = %State{callback: {m, f}}) do
    apply(m, f, [id, ndef])
    state
  end

end
