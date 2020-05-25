open Core
module Symtab = Owee_elf.Symbol_table
module Strtab = Owee_elf.String_table
module Sym = Owee_elf.Symbol_table.Symbol
module Elf_addr = Int64

type sym = Sym.t

type t =
  { map : Owee_buf.t;
    sections : Owee_elf.section array;
    strtab : Strtab.t;
    symtab : Symtab.t;
    resolved_sym : Sym.t option Hashtbl.M(Elf_addr).t
  }

let verbose = ref false

let create ~elf_executable =
  let fd = Unix.openfile elf_executable ~mode:[Unix.O_RDONLY] ~perm:0 in
  let len = Unix.lseek fd 0L ~mode:Unix.SEEK_END |> Int64.to_int_exn in
  let map =
    Bigarray.array1_of_genarray
      (Unix.map_file fd Bigarray.int8_unsigned Bigarray.c_layout
         ~shared:false [| len |])
  in
  Unix.close fd;
  let _header, sections = Owee_elf.read_elf map in
  let resolved_sym = Hashtbl.create (module Elf_addr) in
  let strtab = Owee_elf.find_string_table map sections in
  let symtab = Owee_elf.find_symbol_table map sections in
  match (symtab, strtab) with
  | None, _ -> failwith "Can't find symbol table in elf binary"
  | _, None -> failwith "Can't find string table in elf binary"
  | Some symtab, Some strtab ->
      { map; sections; strtab; symtab; resolved_sym }

let _is_function sym =
  match Sym.type_attribute sym with
  | Func -> true
  | Notype | Object | Section | File | Common | TLS | GNU_ifunc | Other _ ->
      false

let _is_local sym =
  match Sym.binding_attribute sym with
  | Local -> true
  | Global | Weak | GNU_unique | Other _ -> false

let get_size = Sym.size_in_bytes

let get_name t sym = Sym.name sym t.strtab

let get_name_aux t sym =
  match get_name t sym with
  | None -> "?noname?"
  | Some n -> n

let get_name_opt t sym =
  Option.value_map sym ~default:"None" ~f:(get_name_aux t)

let get_symbol_at t addr =
  if !verbose then printf "get_symbol_at %Lx\n" addr;
  match Hashtbl.find t.resolved_sym addr with
  | Some sym ->
      if !verbose then
        printf "Found sym in cache %s at %Lx\n" (get_name_opt t sym) addr;
      sym
  | None ->
      let start_at_addr sym =
        if Elf_addr.equal addr (Sym.value sym) then Some sym else None
      in
      let syms =
        Symtab.symbols_enclosing_address t.symtab ~address:addr
        |> List.filter_map ~f:start_at_addr
      in
      let res =
        match syms with
        | [] -> None
        | [sym] -> Some sym
        | _ -> (
            if !verbose then
              printf "More than one symbol at %Lx: %s\n" addr
                (String.concat ~sep:"\n"
                   (List.map syms ~f:(fun sym -> get_name_aux t sym)));
            (* if more than one symbol at this address, try to choose symbol
               that has a name and out of these choose a symbol with non-zero
               size or starting with caml, if possible. *)
            let sym_with_names =
              List.filter syms ~f:(fun sym ->
                  Option.is_some (Sym.name sym t.strtab))
            in
            match sym_with_names with
            | [] ->
                assert false
                (* can there be more than one sym without name at each addr? *)
            | [sym] -> Some sym
            | _ -> (
                match
                  List.filter sym_with_names ~f:(fun sym ->
                      Elf_addr.(get_size sym > 0L))
                with
                | [sym] -> Some sym
                | _ -> (
                    match
                      List.filter sym_with_names ~f:(fun sym ->
                          String.is_prefix ~prefix:"caml"
                            (get_name_aux t sym))
                    with
                    | [sym] -> Some sym
                    | _ ->
                        let sym = List.random_element_exn sym_with_names in
                        if !verbose then
                          printf "Choosing random sym at %Lx: %s\n" addr
                            (get_name_aux t sym);
                        Some sym ) ) )
      in
      if !verbose then
        printf "Adding sym to cache %s at %Lx\n" (get_name_opt t res) addr;
      Hashtbl.add_exn t.resolved_sym ~key:addr ~data:res;
      res
