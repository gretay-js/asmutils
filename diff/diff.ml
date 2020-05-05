open Core

let verbose = ref false

let set_verbose v = verbose := v

(* Almost identical to Patdiff_lib.Patdiff_core.patdiff except that it
   instead of output to string*)
let patdiff prev_file prev next_file next =
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
  | [] -> None
  | _ ->
      print ~prev_file ~next_file ~rules ~output
        ~location_style:Format.Location_style.Diff hunks;
      Some ()

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

let parse_sym s =
  match String.split ~on:' ' s with
  | [_start; name] -> (
      try
        name
        |> String.chop_prefix_exn ~prefix:"<"
        |> String.chop_suffix_exn ~suffix:">"
      with _ -> failwithf "Unexpected format\n%s\n" name () )
  | _ -> failwithf "Unexpected format\n%s\n" s ()

let symbolic instr =
  let instr = String.strip instr in
  let res = String.split_on_chars ~on:['\t'; ','] instr in
  List.map res ~f:(fun arg ->
      if String.contains arg ' ' then parse_sym arg else arg)

let symbolic_rip instr ~target =
  let target = String.strip target in
  let sym = parse_sym target in
  let instr = symbolic instr in
  List.map instr ~f:(fun arg ->
      if String.is_suffix arg ~suffix:"%(rip)" then sym else arg)

let parse_func_name line =
  match String.chop_suffix line ~suffix:":" with
  | Some s -> parse_sym s
  | None -> failwithf "Unexpected format %s\n" line ()

let parse_instr line =
  match String.split_on_chars ~on:[':'; '#'] line with
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
        let body = List.tl_exn acc |> List.to_array in
        match String.Table.add asm ~key:name ~data:body with
        | `Ok -> []
        | `Duplicate ->
            failwithf "Duplicate function name %s. May be local function."
              name () )
  else if String.is_prefix line ~prefix:file then
    match String.chop_suffix line ~suffix:"file format elf64" with
    | None -> failwithf "Unexpect format: %s\n" line ()
    | Some _ -> acc
  else if String.is_prefix line ~prefix:"Disassembly of section .text" then
    acc
  else
    match acc with
    | [] -> [parse_func_name line]
    | body ->
        let instr = parse_instr line |> String.concat ~sep:" " in
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
    | `Both (b1, b2) -> patdiff file1 b1 file2 b2
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
  let old_names = sort !removed in
  let new_names = sort !added in
  ignore (patdiff file1 old_names file2 new_names : unit option);
  ()

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
