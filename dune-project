(lang dune 2.0)
(formatting (enabled_for dune ocaml))
(name asmutils)
(version 0.0.1)

(license MIT)
(maintainers "Greta Yorsh <gyorsh@janestreet.com>")
(authors "Jane Street Group, LLC <opensource@janestreet.com>")
(source (github gretay-js/asmutils))

(package
 (name asmutils)
 (synopsis "asmutils")
 (description "
Experimental.
Copyright (c) 2019 Jane Street Group LLC.
")
 (depends
  (ocaml (>= 4.09))
  (dune (>= 1.8))
  owee
  core
  ppx_jane
 )
)


(generate_opam_files true)
