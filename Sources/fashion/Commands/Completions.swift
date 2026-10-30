import ArgumentParser

/**
 The completion scripts, made to complete a command line as the parser reads it.

 swift-argument-parser completes the arguments of a subcommand only once its name is on the command line
 (apple/swift-argument-parser#488): neither the default subcommand nor an alias completes anything, so
 `fashion /tmp/<TAB>` and `fashion thinr <TAB>` offer nothing. Each script it generates comes with a wrapper that rewrites
 the words the generated one reads, as the parser reads them: an alias becomes its subcommand, and words that name no
 subcommand are the default subcommand's. On the second word, the subcommands are offered beside what the default
 subcommand takes.
 */
extension Fashion {
    /**
     The shell a completion script is asked for, read as the parser reads --generate-completion-script: anywhere
     before `--`, the last one given, with the shell after `=` or as the next argument, else the user's own.
     */
    static var requestedCompletionShell: CompletionShell? {
        let option = "--generate-completion-script"
        let arguments = CommandLine.arguments.dropFirst().prefix { $0 != "--" }
        guard let index = arguments.lastIndex(where: { $0 == option || $0.hasPrefix(option + "=") }) else {
            return nil
        }
        if arguments[index].count > option.count + 1 {
            return CompletionShell(rawValue: String(arguments[index].dropFirst(option.count + 1)))
        }
        if index + 1 < arguments.endIndex, !arguments[index + 1].hasPrefix("-") {
            return CompletionShell(rawValue: arguments[index + 1])
        }
        return CompletionShell.autodetected()
    }

    /// The completion script for `shell` as the parser generates it, with the wrapper.
    static func wrappedCompletionScript(for shell: CompletionShell) -> String {
        let script = self.completionScript(for: shell)
        guard let main = self.configuration.defaultSubcommand?.configuration.commandName else {
            return script
        }
        // `help` is the parser's own.
        let commands = self.configuration.subcommands.compactMap { command in
            command.configuration.commandName.map { (name: $0, aliases: command.configuration.aliases) }
        } + [(name: "help", aliases: [])]
        let aliased = commands.filter { !$0.aliases.isEmpty }
        let names = commands.map(\.name)
        let comment = "# As the parser reads them: an alias names its subcommand, and words that name none are \(main)'s."

        switch shell {
        case .fish:
            let cases = aliased.map { "        case \($0.aliases.joined(separator: " "))\n            set tokens[2] \($0.name)\n" }
            return script + """


            \(comment)
            functions -e __fashion_command_line_tokens
            functions -c __fashion_tokens __fashion_command_line_tokens
            function __fashion_tokens
                set -l tokens (__fashion_command_line_tokens $argv)
                # -pc for the conditions, -p for the words a custom completion hands back to fashion.
                if string match -q -- '-p*' "$argv"; and test (count $tokens) -ge 2
                    switch $tokens[2]
            \(cases.joined())\
                    case \(names.joined(separator: " "))
                    case '*'
                        set tokens $tokens[1] \(main) $tokens[2..]
                    end
                end
                string join \\n -- $tokens
            end

            complete -c fashion -n 'test (count (__fashion_tokens -pc)) -eq 1' \
            -a '(complete -C "fashion \(main) "(commandline -ct))'
            """
        case .bash:
            let cases = aliased.map { "        \($0.aliases.joined(separator: "|"))) COMP_WORDS[1]=\($0.name) ;;\n" }
            return script + """


            \(comment)
            __fashion_function="$(declare -f _fashion)"
            eval "__fashion_command_line${__fashion_function#_fashion}"
            unset __fashion_function

            _fashion() {
                local -a COMP_WORDS=("${COMP_WORDS[@]}")
                local -i COMP_CWORD="${COMP_CWORD}"
                if [[ "${COMP_CWORD}" -gt 1 ]]; then
                    case "${COMP_WORDS[1]}" in
            \(cases.joined())\
                    \(names.joined(separator: "|"))) ;;
                    *) COMP_WORDS=("${COMP_WORDS[0]}" \(main) "${COMP_WORDS[@]:1}"); COMP_CWORD+=1 ;;
                    esac
                else
                    __fashion_command_line "${@}"
                    COMP_WORDS=("${COMP_WORDS[0]}" \(main) "${COMP_WORDS[@]:1}")
                    COMP_CWORD+=1
                fi
                __fashion_command_line "${1}" "${2}" "${COMP_WORDS[COMP_CWORD - 1]}"
            }
            """
        case .zsh:
            let cases = aliased.map { "        \($0.aliases.joined(separator: "|"))) words[2]=\($0.name) ;;\n" }
            let wrapper = """
            \(comment)
            functions[__fashion_command_line]="${functions[_fashion]}"

            _fashion() {
                local -i ret=1
                if (( CURRENT > 2 )); then
                    case "${words[2]}" in
            \(cases.joined())\
                    \(names.joined(separator: "|"))) ;;
                    *) words=("${words[1]}" \(main) "${(@)words[2,-1]}"); (( CURRENT++ )) ;;
                    esac
                else
                    local -ar command_words=("${words[@]}")
                    __fashion_command_line "${@}" && ret=0
                    words=("${command_words[1]}" \(main) "${(@)command_words[2,-1]}")
                    (( CURRENT++ ))
                fi
                __fashion_command_line "${@}" && ret=0

                return "${ret}"
            }


            """
            // Before the lines that call `_fashion` when the script is autoloaded as the function itself.
            guard let tail = script.ranges(of: "\nif [[ \"${funcstack[1]}\" = _fashion ]]").last else {
                return script + "\n" + wrapper
            }
            let index = script.index(after: tail.lowerBound)
            return String(script[..<index]) + wrapper + String(script[index...])
        default:
            return script
        }
    }
}
