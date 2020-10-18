;;; magic.scm --- determine file types via libmagic

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

;; This module provides for guessing file types via libmagic <http://www.darwinsys.com/file/>.

;; It uses Guile's Dynamic FFI system to talk directly to libmagic (without the intermediary of
;; a C extension to Guile) and provides a Scheme API over the raw C API offered by libmagic:

;; scheme@(guile-user)> (use-modules (magic))
;; scheme@(guile-user)> (magic-file-type "/usr/bin/file")
;; $2 = "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2b26928f841d92afa31613c2c916a3abc96bbed8, stripped"

;;; Code:

(define-module (magic)
  #:export (magic-file-type magic-buffer-type)
  #:use-module (ice-9 optargs)
  #:use-module (magic vars)
  #:use-module (magic magic)
  #:re-export (%magic-version %magic-semver %magic-datadir magic-error magic-version <magic-set>
               magic-set? make-magic-set magic-file magic-buffer
               magic-none magic-debug magic-symlink magic-compress magic-devices
               magic-mime-type magic-continue magic-check magic-preserve-atime magic-raw magic-error
               magic-mime-encoding magic-mime magic-apple magic-extension
               magic-compress-transp magic-nodesc magic-no-check-compress
               magic-no-check-tar magic-no-check-soft magic-no-check-apptype
               magic-no-check-elf magic-no-check-text magic-no-check-cdf magic-no-check-csv
               magic-no-check-tokens magic-no-check-encoding magic-no-check-json
               magic-param-indir-max magic-param-name-max magic-param-elf-phnum-max
               magic-param-elf-shnum-max magic-param-elf-notes-max magic-param-regex-max
               magic-param-bytes-max))

(define* (magic-file-type filename #:key magic opts params)
  "Return a textual description of the contents of FILENAME."
  (let ((m (make-magic-set #:magic magic #:opts opts #:params params)))
    (magic-file m filename)))

(define* (magic-buffer-type buf #:optional cbbuf #:key magic opts params)
  "Return a textual description of the contents of BUF."
  (let ((m (make-magic-set #:magic magic #:opts opts #:params params)))
    (magic-buffer m buf cbbuf)))

;;; magic.scm ends here.
