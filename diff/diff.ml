open Core

let verbose = ref false

let set_verbose v = verbose := v

let emit_sym s = sprintf "<%s>" s

(* Almost identical to Patdiff_lib.Patdiff_core.patdiff except that it
   instead of output to string*)
let patdiff ~name1 ~file1 prev ~name2 ~file2 next =
  let header file name = sprintf "%s in %s" (emit_sym name) file in
  let prev_file = header file1 name1 in
  let next_file = header file2 name2 in
  let open Patdiff_lib.Patdiff_core in
  let rules = Format.Rules.default in
  let output = Output.Ansi in
  let keep_ws = false in
  let hunks =
    diff ~context:default_context ~keep_ws
      ~line_big_enough:default_line_big_enough ~prev ~next
    |> refine ~rules ~produce_unified_lines:true ~output ~keep_ws
         ~split_long_lines:true ~interleave:true
         ~word_big_enough:default_word_big_enough
  in
  match hunks with
  | [] -> `Same
  | _ ->
      print ~prev_file ~next_file ~rules ~output
        ~location_style:Format.Location_style.Diff hunks;
      print_endline "";
      `Different ()

let objdump_fold file ~init ~f =
  let cmd = "objdump -d -j .text -M amd64 --no-show-raw-insn -w " in
  let args = String.split ~on:' ' (cmd ^ file) in
  if !verbose then Printf.printf "%s\n" (String.concat ~sep:" " args);
  let open Shexp_process in
  let open Shexp_process.Infix in
  let f x y = return (f x y) in
  let t, sexp =
    Traced.eval ~capture:true (call args |- fold_lines ~init ~f)
  in
  if !verbose then print_endline (Sexp.to_string_hum sexp);
  match t with
  | Ok t -> t
  | _ -> failwithf "Unexpected output of %s" (String.concat ~sep:" " args) ()

let chop_symbol_suffix s =
  match String.rindex s '_' with
  | None -> s
  | Some i -> String.sub ~pos:0 ~len:i s

let parse_sym s =
  let s = String.strip s in
  match String.split ~on:' ' s with
  | [_start; name] -> (
      try
        name
        |> String.chop_prefix_exn ~prefix:"<"
        |> String.chop_suffix_exn ~suffix:">"
      with _ -> failwithf "Unexpected format\n%s\n" name () )
  | _ -> failwithf "Unexpected format\n%s\n" s ()

let emit_func_name n = emit_sym n ^ ":"

let emit_args s = String.concat ~sep:"," s

let emit_op op = sprintf "%-7s " op

let emit_instr s =
  match s with
  | [op] -> emit_op op
  | "rep" :: op :: args -> emit_op ("rep " ^ op) ^ emit_args args
  | op :: args -> emit_op op ^ emit_args args
  | _ ->
      failwithf "Unexpected format, cannot emit instr %s"
        (String.concat ~sep:" " s)
        ()

let symbolic instr =
  let instr = String.strip instr in
  match String.split_on_chars ~on:[','] instr with
  | op_and_arg :: otherargs ->
      let op_and_args = String.strip op_and_arg in
      let args =
        match String.lsplit2 ~on:' ' op_and_args with
        | None -> op_and_args :: otherargs
        | Some (("rep" as rep), arg) -> (
            let arg = String.strip arg in
            match String.lsplit2 ~on:' ' arg with
            | None -> rep :: arg :: otherargs
            | Some (op, arg) -> rep :: op :: arg :: otherargs )
        | Some (op, arg) -> op :: arg :: otherargs
      in
      List.map args ~f:(fun arg ->
          let arg = String.strip arg in
          if String.contains arg ' ' then parse_sym arg |> emit_sym else arg)
  | _ -> failwithf "Unexpected format of instruction: %s" instr ()

let symbolic_rip instr ~target =
  let sym = parse_sym target in
  let instr = symbolic instr in
  List.map instr ~f:(fun arg ->
      if String.is_suffix arg ~suffix:"(%rip)" then emit_sym sym else arg)

let parse_func_name line =
  match String.chop_suffix line ~suffix:":" with
  | Some s -> parse_sym s
  | None -> failwithf "Unexpected format %s\n" line ()

let parse_instr line =
  match String.split_on_chars ~on:['\t'; '#'] line with
  | [_addr; instr] -> symbolic instr
  | [_addr; instr; target] -> symbolic_rip instr ~target
  | _ -> failwithf "Unexpected instruction disassembly\n%s\n" line ()

let parse_line ~file ~asm acc line =
  let line = String.strip line in
  if String.is_empty line then
    match acc with
    | [] -> acc (* empty line before the first function *)
    | _ -> (
        let acc = List.rev acc in
        let name = List.hd_exn acc in
        let body = emit_func_name name :: List.tl_exn acc |> List.to_array in
        match String.Table.add asm ~key:name ~data:body with
        | `Ok -> []
        | `Duplicate ->
            failwithf "Duplicate function name %s. May be local function."
              name () )
  else if String.is_prefix line ~prefix:file then
    match String.chop_suffix line ~suffix:"file format elf64-x86-64" with
    | None -> failwithf "Unexpect format: %s\n" line ()
    | Some _ -> acc
  else if String.is_prefix line ~prefix:"Disassembly of section .text" then
    acc
  else
    match acc with
    | [] -> [parse_func_name line]
    | body ->
        let instr = parse_instr line |> emit_instr in
        instr :: body

let disass file =
  let asm = String.Table.create () in
  let f = parse_line ~file ~asm in
  let last = objdump_fold file ~init:[] ~f in
  match f last "" with
  | [] -> asm
  | _ -> assert false

let main file1 file2 =
  if !verbose then printf "Compare files: %s\n %s\n" file1 file2;
  let asm1 = disass file1 in
  let asm2 = disass file2 in
  let removed = ref [] in
  let added = ref [] in
  let f ~key:name = function
    | `Left _ ->
        removed := name :: !removed;
        None
    | `Right _ ->
        added := name :: !added;
        None
    | `Both (b1, b2) -> (
        match patdiff ~name1:name ~name2:name ~file1 b1 ~file2 b2 with
        | `Same -> None
        | `Different _ -> Some () )
  in
  let diff = String.Table.merge asm1 asm2 ~f in
  if !verbose then (
    List.iter !removed ~f:(fun s -> printf "deleted %s\n" s);
    List.iter !added ~f:(fun s -> printf "added %s\n" s);
    String.Table.iter_keys diff ~f:(fun s -> printf "differ %s\n" s) );
  let sort l =
    let a = Array.of_list l in
    Array.sort ~compare:String.compare a;
    a
  in
  if not (List.is_empty !removed && List.is_empty !added) then
    let old_names = sort !removed in
    let new_names = sort !added in
    let new_name_prefixes = Array.map new_names ~f:chop_symbol_suffix in
    let matched_new_names = String.Table.create () in
    let old_names =
      Array.filteri old_names ~f:(fun i old_name ->
          let prefix = chop_symbol_suffix old_name in
          if !verbose then
            printf "match for prefix=%s old_name=%s\n" prefix old_name;
          let f _ s = String.equal prefix s in
          let same_prefix arr ~at =
            if at < Array.length arr then f 0 (chop_symbol_suffix arr.(at))
            else false
          in
          if same_prefix old_names ~at:(i + 1) then
            (* more than one old name with this prefix: don't refine the diff *)
            true
          else
            match Array.findi new_name_prefixes ~f with
            | None -> true
            | Some (j, _) ->
                let new_name = new_names.(j) in
                if !verbose then
                  printf "match for prefix=%s new_name=%s\n" prefix new_name;
                if same_prefix ~at:(j + 1) new_names then
                  (* more than one new name with this prefix: don't refine
                     the diff *)
                  true
                else (
                  if !verbose then
                    printf "matching:\nold: %s\nnew: %s\n" old_name new_name;
                  String.Table.add_exn matched_new_names ~key:new_name
                    ~data:();
                  match
                    patdiff ~name1:old_name ~name2:new_name ~file1 ~file2
                      (String.Table.find_exn asm1 old_name)
                      (String.Table.find_exn asm2 new_name)
                  with
                  | `Same | `Different _ -> false ))
    in
    let new_names =
      Array.filter new_names ~f:(fun s ->
          match String.Table.find matched_new_names s with
          | None -> true
          | Some _ -> false)
    in
    let symbols = "symbols" in
    match
      patdiff ~name1:symbols ~name2:symbols ~file1 old_names ~file2 new_names
    with
    | `Same | `Different _ -> ()

let main_command =
  let open Command.Param in
  Command.basic
    ~summary:
      "Pattdiff disassembly of two ELF executables function by function"
    Command.Let_syntax.(
      let%map v =
        flag "-verbose" ~aliases:["-v"] no_arg ~doc:" debug printouts"
      and pair =
        anon
          (t2 ("FILE1" %: Filename.arg_type) ("FILE2" %: Filename.arg_type))
      in
      if v then set_verbose true;
      let prev, next = pair in
      fun () -> main prev next)

let () = Command.run main_command
