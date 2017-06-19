defmodule NervesIoNfc.Mixfile do
  use Mix.Project

  def project do
    [app: :nerves_io_nfc,
     version: "0.1.0",
     elixir: "~> 1.3",
     name: "nerves_io_nfc",
     description: description(),
     package: package(),
     source_url: "https://github.com/ChristopheBelpaire/nerves_io_nfc.git",
     compilers: [:elixir_make] ++ Mix.compilers,
     make_clean: ["clean"],
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  def application do
    [applications: [:logger]]
  end

  defp description do
  """
  Elixir access to LibNFC-compatible USB NFC readers
  """
  end

  defp package do
    %{files: ["lib", "src/*.[ch]", "mix.exs", "README.md", "LICENSE", "Makefile", "*.mk", "priv/*"],
      maintainers: ["Arjan Scherpenisse"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/ChristopheBelpaire/nerves_io_nfc.git"}}
  end

  defp deps do
    [
      {:elixir_make, "~> 0.3"}
    ]
  end
end
