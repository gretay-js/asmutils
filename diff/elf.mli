open Core

type t

type sym

module Elf_addr = Int64

val create : elf_executable:string -> t

val get_symbol_at : t -> Elf_addr.t -> sym option

val verbose : bool ref

val get_name : t -> sym -> string option
