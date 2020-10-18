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
(test-equal "JPEG image data" (magic-buffer-type buf))

;; Finish the testsuite, and report results.
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

(test-end "option-tests")

(test-begin "param-tests")

(let* ((srcdir (getenv "srcdir"))
       (lorem (format #f "~a/data/lorem.txt.gz" srcdir)))
  (string-prefix?
   "gzip compressed data"
   (magic-file-type
    lorem
    #:params '((magic-param-elf-notes-max . 512) (magic-param-bytes-max . 1024)))))

(test-end "param-tests")

(test-begin "magic-tests")

(define buf (make-bytevector 2))
(bytevector-u8-set! buf 0 255)
(bytevector-u8-set! buf 1 216)

;; (define m (make-magic-set #:opts 1 #:magic "./data/test-magic"))
;; (magic-buffer m buf)

(let* ((srcdir (getenv "srcdir"))
       (magic (format #f "~a/data/test-magic" srcdir)))
  (test-equal "JPEG image data" (magic-buffer-type buf #:magic magic)))

(test-end "magic-tests")

(test-begin "negative-tests")

(test-error #t (make-magic-set #:magic "/foo/bar/splat"))

(test-end "negative-tests")

(exit (eq? (test-runner-fail-count (test-runner-get)) 0))
