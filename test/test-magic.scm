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

;;; coding: UTF-8

(use-modules (ice-9 format))
(use-modules (rnrs bytevectors))
(use-modules (srfi srfi-64))

(define num_failures 0)

(test-begin "smoke-tests")

(use-modules (magic))

(test-equal
 %magic-version
 (apply format #f "~d.~d.~d" %magic-semver))

(test-assert (> (magic-version) 0))

(let* ((srcdir (getenv "srcdir"))
       (a (format #f "~a/data/a" srcdir)))
  (test-assert (string-suffix? "empty" (magic-file-type a))))

(define buf (make-bytevector 2))
(bytevector-u8-set! buf 0 255)
(bytevector-u8-set! buf 1 216)
(test-equal "ISO-8859 text, with no line terminators" (magic-buffer-type buf))

(set! num_failures (+ num_failures (test-runner-fail-count (test-runner-get))))

(test-end "smoke-tests")

(test-begin "option-tests")

(let* ((srcdir (getenv "srcdir"))
       (lorem (format #f "~a/data/lorem.txt.gz" srcdir)))
  (string-prefix? "gzip compressed data" (magic-file-type lorem))
  (string-prefix?
   "text/plain; charset=us-ascii"
   (magic-file-type lorem #:opts (list magic-compress magic-mime-type)))
  (string-prefix?
   "text/plain; charset=us-ascii"
   (magic-file-type lorem #:opts #x14)))

(set! num_failures (+ num_failures (test-runner-fail-count (test-runner-get))))

(test-end "option-tests")

(test-begin "param-tests")

(let* ((srcdir (getenv "srcdir"))
       (lorem (format #f "~a/data/lorem.txt.gz" srcdir)))
  (string-prefix?
   "gzip compressed data"
   (magic-file-type
    lorem
    #:params '((magic-param-elf-notes-max . 512) (magic-param-bytes-max . 1024)))))

(set! num_failures (+ num_failures (test-runner-fail-count (test-runner-get))))

(test-end "param-tests")

(test-begin "magic-tests")

(define buf (make-bytevector 2))
(bytevector-u8-set! buf 0 255)
(bytevector-u8-set! buf 1 216)

(let* ((srcdir (getenv "srcdir"))
       (magic (format #f "~a/data/test-magic" srcdir)))
  (test-equal "ISO-8859 text, with no line terminators" (magic-buffer-type buf)))

(set! num_failures (+ num_failures (test-runner-fail-count (test-runner-get))))

(test-end "magic-tests")

(test-begin "negative-tests")

(test-error #t (make-magic-set #:magic "/foo/bar/splat"))

(set! num_failures (+ num_failures (test-runner-fail-count (test-runner-get))))

(test-end "negative-tests")

(exit (eq? num_failures 0))
