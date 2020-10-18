;;; magic.scm --- low-level interface libmagic

;; Copyright (C) 2020 Michael Herstine <sp1ff@pobox.com>

;; This program is free software: you can redistribute it and/or modify it under the terms of the
;; GNU General Public License as published by the Free Software Foundation; either version 3 of the
;; License, or (at your option) any later version.

;; This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
;; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
;; the GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License along with this program. If
;; not, see https://www.gnu.org/licenses/.

;;; Commentary:

;; I initially considered writing a C extension, but the libmagic API is straightforward enough
;; that Guile's Dynamic FFI will suffice.  Of course, when working through Dynamic FFI one has to
;; constantly convert back & forth between Scheme & C, e.g.
;;
;;     (pointer->string (raw-magic-getpath (string->pointer myvar) my-action))
;;
;; and getting a conversion wrong can corrupt memory or cause a SEGV.  Therefore, this module keeps
;; all the low-level communication between Scheme & C internal & exports an API that wraps it.

;;; Code:

(define-module (magic magic)
  #:export (magic-error magic-version <magic-set> magic-set? make-magic-set magic-file magic-buffer
            magic-none magic-debug magic-symlink magic-compress magic-devices
            magic-mime-type magic-continue magic-check magic-preserve-atime magic-raw magic-error
            magic-mime-encoding magic-mime magic-apple magic-extension
            magic-compress-transp magic-nodesc magic-no-check-compress
            magic-no-check-tar magic-no-check-soft magic-no-check-apptype
            magic-no-check-elf magic-no-check-text magic-no-check-cdf magic-no-check-csv
            magic-no-check-tokens magic-no-check-encoding magic-no-check-json
            magic-param-indir-max magic-param-name-max magic-param-elf-phnum-max
            magic-param-elf-shnum-max magic-param-elf-notes-max magic-param-regex-max
            magic-param-bytes-max)
  #:use-module (ice-9 iconv)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-9)
  #:use-module (system foreign)
  #:use-module (magic vars))

;;; Flags that affect checking magic
(define	magic-none		          #x0000000) ;; No flags
(define	magic-debug		          #x0000001) ;; Turn on debugging
(define	magic-symlink		        #x0000002) ;; Follow symlinks
(define	magic-compress		      #x0000004) ;; Check inside compressed files
(define	magic-devices		        #x0000008) ;; Look at the contents of devices
(define	magic-mime-type         #x0000010) ;; Return the MIME type
(define	magic-continue          #x0000020) ;; Return all matches
(define	magic-check             #x0000040) ;; Print warnings to stderr
(define	magic-preserve-atime    #x0000080) ;; Restore access time on exit
(define	magic-raw               #x0000100) ;; Don't convert unprintable chars
(define	magic-error             #x0000200) ;; Handle ENOENT etc as real errors
(define	magic-mime-encoding     #x0000400) ;; Return the MIME encoding
(define	magic-apple             #x0000800) ;; Return the Apple creator/type
(define	magic-extension         #x1000000) ;; Return a /-separated list of extensions
(define magic-compress-transp   #x2000000) ;; Check inside compressed files but not report compression
(define	magic-no-check-compress #x0001000) ;; Don't check for compressed files
(define	magic-no-check-tar      #x0002000) ;; Don't check for tar files
(define	magic-no-check-soft     #x0004000) ;; Don't check magic entries
(define	magic-no-check-apptype  #x0008000) ;; Don't check application type
(define	magic-no-check-elf      #x0010000) ;; Don't check for elf details
(define	magic-no-check-text     #x0020000) ;; Don't check for text files
(define	magic-no-check-cdf      #x0040000) ;; Don't check for cdf files
(define magic-no-check-csv      #x0080000) ;; Don't check for CSV files
(define	magic-no-check-tokens   #x0100000) ;; Don't check tokens
(define magic-no-check-encoding #x0200000) ;; Don't check text encodings
(define magic-no-check-json     #x0400000) ;; Don't check for JSON files

(define magic-mime   (logior magic-mime-type magic-mime-encoding))
(define magic-nodesc (logior magic-extension magic-mime magic-apple))

;;; Parameters internal to the magic-checking algorithm

;; Name                         Default    Explanation
;; magic-param-indir-max        15         recursion limit for indirect magic
;; magic-param-name-max         30         use count limit for name/use magic
;; magic-param-elf-notes-max    256        max ELF notes processed
;; magic-param-elf-phnum-max    128        max ELF program sections processed
;; magic-param-elf-shnum-max    32768      max ELF sections processed
;; magic-param-regex-max        8192       length limit for regex searches
;; magic-param-bytes-max        1048576    max number of bytes to read from file

(define magic-params
  `((magic-param-indir-max . (0 65535))
    (magic-param-name-max . (1 65535))
    (magic-param-elf-phnum-max . (2 65535))
    (magic-param-elf-shnum-max . (3 65535))
    (magic-param-elf-notes-max . (4 65535))
    (magic-param-regex-max . (5 65535))
    (magic-param-bytes-max . (6 ,(case (sizeof '*)
                                   ((4) 4294967295)
                                   ((8) 18446744073709551615)
                                   (else (error "Unsupported platform")))))))

;;; Raw function pointers

;; NB. We don't load magic_descriptor or magic_load_buffers (no use).

(define libmagic (dynamic-link "libmagic"))

(define raw-magic-open
  (pointer->procedure '* (dynamic-func "magic_open" libmagic) (list int)))
(define raw-magic-close
  (pointer->procedure void (dynamic-func "magic_close" libmagic) (list '*)))
(define raw-magic-getpath
  (pointer->procedure '* (dynamic-func "magic_getpath" libmagic) (list '* int)))
(define raw-magic-file
  (pointer->procedure '* (dynamic-func "magic_file" libmagic) (list '* '*)))
(define raw-magic-buffer
  (pointer->procedure '* (dynamic-func "magic_buffer" libmagic) (list '* '* size_t)))
(define raw-magic-error
  (pointer->procedure '* (dynamic-func "magic_error" libmagic) (list '*)))
(define raw-magic-getflags
  (pointer->procedure int (dynamic-func "magic_getflags" libmagic) (list '*)))
(define raw-magic-setflags
  (pointer->procedure int (dynamic-func "magic_setflags" libmagic) (list '* int)))
(define raw-magic-version
  (pointer->procedure int (dynamic-func "magic_version" libmagic) '()))
(define raw-magic-load
  (pointer->procedure int (dynamic-func "magic_load" libmagic) (list '* '*)))
(define raw-magic-compile
  (pointer->procedure int (dynamic-func "magic_compile" libmagic) (list '* '*)))
(define raw-magic-check
  (pointer->procedure int (dynamic-func "magic_check" libmagic) (list '* '*)))
(define raw-magic-list
  (pointer->procedure int (dynamic-func "magic_list" libmagic) (list '* '*)))
(define raw-magic-errno
  (pointer->procedure int (dynamic-func "magic_errno" libmagic) (list '*)))
(define raw-magic-setparam
  (pointer->procedure int (dynamic-func "magic_setparam" libmagic) (list '* int '*)))
(define raw-magic-getparam
  (pointer->procedure int (dynamic-func "magic_getparam" libmagic) (list '* int '*)))

;;; First Scheme API

;; Now let's define a Scheme-ish API to libmagic.

(define (magic-version)
  (raw-magic-version))

;; This is the analog to libmagic's `magic_t'-- an opaque handle to a `magic_set' struct. In order
;; to get finer-grained control, we export the type & the predicate, but not the constructor nor
;; any accessor or mutator. guile-magic users can call `make-magic-set', below, to get new
;; instances.
(define-record-type <magic-set>
  (new-magic-set cookie)
  magic-set?
  (cookie magic-set-cookie magic-set-cookie!))

(define guard (make-guardian))

(define (finalize)
  "Close any <magic-set> instances that are no longer reachable."
  (let ((dead (guard)))
    (while dead
           (raw-magic-close (magic-set-cookie dead))
           (set! dead (guard)))))

(define* (make-magic-set #:key magic opts params)
  "Create a new magic set.

Invoking this method with no parameters will produce a <magic-set> instance that will behave as if
you'd invoked `file' on your system with no options. That said, the keyword arguments #:magic #:opts
and #:params give fine-grained control over how magic will be applied:

#:magic controls where the <magic-set> will obtain magic to use in subsequent operations. If given,
it may be a list of strings naming files or directories to be checked, or it may be a single
string containing a colon-delimited path to be checked. Compiled magic files found alongside
files or directories named herein will be used instead.

If not specified, magic will be found as follows:

    1. if the MAGIC environment variable is set, use that

    2. else, if ${HOME}/.magic.mgc exists, use ${HOME}/.magic.mgc:MAGIC, where MAGIC is the C
       preprocessor variable with which libmagic was built

    3. else, if ${HOME}/.magic does not exist, MAGIC

    4. else, if ${HOME}/.magic is not a directory, use ${HOME}/.magic:MAGIC

    5. else, if ${HOME}/.magic/magic.mgc exists, use ${HOME}/.magic/magic.mgc:MAGIC

    6. finally, if all else fails, just use MAGIC

The C preprocessor variable MAGIC is set to \"/etc/magic\" in code, but it is generally customized
at compile-time. For instance, if the source distribution is downloaded from
<ftp://ftp.astron.com/pub/file>, configured with the default settings & made, it will be changed to
${pkgdatadir}/magic. Ubuntu customizes
<https://git.launchpad.net/ubuntu/+source/file/tree/debian/patches/local.support-local-definitions-in-etc-magic.patch?h=applied/ubuntu/devel>
it to ${pkgdatadir}/magic:/etc/magic.

#:opts controls assorted options for handling files & applying magic (cf. `magic-debug',
`magic-symlink' &c). If not specified, the default of `magic-none' will be used, unless the
environment variable POSIXLY_CORRECT is not set, in which case `magic-symlinks' will be.

The options are not keywords, but integers whose values are distinct powers of two, meaning
they can be logically or'd together without loss of information. Therefore, the caller may
specify #:opts as a list of options, or as a single integer whose value is a combination
of the desired values.

#:params controls limits on assorted parameters internal to the algorithm (recursion limits, buffer
sizes &c). Each takes an integral value; if the caller wishes to change them, they shall be a list
of cons cells each of whose cars is the parameter to be set (cf. `magic-param-*' and whose cdr
is the value to be used).

A call to `make-magic-set' will result in a call to `magic_open' being made. However, there is
no need for the caller to arrange for the corresponding call to `magic_close'; <magic-set> is
tied into the Scheme garbage collector & should clean itself up."

  (let* ((magic
          (cond
           ((list? magic)
            (string-join magic ":"))
           ((string? magic)
            magic)
           ((not magic)
            (pointer->string (raw-magic-getpath %null-pointer 0)))
           (#t
            (error "#:magic must be either a string or list of strings"))))
         (opts
          (cond
           ((list? opts) (apply logior opts))
           ((integer? opts) opts)
           ((not opts)
            (if (getenv "POSIXLY_CORRECT") magic-symlink magic-none))
           (#t (error "#:opts must be an integer or a list of integers"))))
         (cookie
          (raw-magic-open opts)))
    (finalize)
    (if (eq? -1 (raw-magic-load cookie (string->pointer magic)))
        (begin
          (let ((err-text (pointer->string (raw-magic-error cookie))))
            (raw-magic-close cookie)
            (error "Failed to load magic ~a (~s)" magic err-text))))
    (if params
        (while (> (length params) 0)
               (let* ((param (car params))
                      (sym (car param))
                      (val (cdr param))
                      (defn-value (car (assq-ref magic-params sym)))
                      (max-value (cadr (assq-ref magic-params sym)))
                      (buf (make-bytevector (sizeof '*) 0)))
                 (if (or (< val 0) (> val max-value))
                     (error "Illegal value for ~a: ~s" sym val))
                 (case (sizeof '*)
                   ((4) bytevector-u32-native-set! buf 0 val)
                   ((8) (bytevector-u64-native-set! buf 0 val))
                   (else (error "Unsupported platform")))
                 (if (eq? -1 (raw-magic-setparam cookie defn-value (bytevector->pointer buf)))
                     (begin
                       (let ((err-text (pointer->string (raw-magic-error cookie))))
                         (raw-magic-close cookie)
                         (error "Failed to set parameter: ~s (~a)" param err-text)))))
               (set! params (cdr params))))
    (let ((magic-set (new-magic-set cookie)))
      (guard magic-set)
      magic-set)))

(define (magic-error magic-set)
  (pointer->string (raw-magic-error (magic-set-cookie magic-set))))

(define (magic-file magic-set filename)
  "Determine the type of FILENAME via MAGIC-SET."
  (finalize)
  (pointer->string (raw-magic-file (magic-set-cookie magic-set) (string->pointer filename))))

(define* (magic-buffer magic-set buf #:optional cbbuf)
  "Determine the type of data in BUF via MAGIC-SET."
  (finalize)
  (let ((n (if cbbuf cbbuf (bytevector-length buf))))
    (pointer->string
     (raw-magic-buffer
      (magic-set-cookie magic-set)
      (bytevector->pointer buf)
      n))))

;;; magic.scm ends here
