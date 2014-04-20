(*
 * Copyright (c) 2014, Javier M. Mellid <javier@javiermunhoz.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *)

module type W32h0rtiga_type = sig
   type t
   val  infected  : string -> (bool * t)
   val  disinfect : string -> t -> bool
end

module W32h0rtiga : W32h0rtiga_type = struct

type vir_t = {
        n_sections        : int; (* number of sections *)
        n_sections_off    : int; (* number of sections offset *)
        sz_opt_header     : int; (* size optional header *)
        rva_ep            : int; (* relative virtual address entry point *)
        rva_ep_off        : int; (* relative virtual address entry point offset *)
        img_base          : int; (* image base *)
        w32vv_off         : int; (* win32 version value offset *)
        viral_section_off : int; (* viral section offset *)
        virt_address      : int; (* last section virtual address *)
        sz_raw_address    : int; (* last section size raw address *)
        raw_address       : int; (* last section raw address *)
        charact           : int; (* last section characteristics *)
        old_ep            : int  (* old entry point *)
}

type t = vir_t option

let disinfect file t =
  match t with
  | Some vm ->
        let bits = Bitstring.bitstring_of_file file in
        let s1 = (Bitstring.subbitstring bits 0 (vm.n_sections_off)) in
        let s2 = (Bitstring.subbitstring bits (vm.n_sections_off+16)
                                              (vm.rva_ep_off-(vm.n_sections_off+16))) in
        let s3 = (Bitstring.subbitstring bits (vm.rva_ep_off+32)
                                              (vm.w32vv_off-(vm.rva_ep_off+32))) in
        let s4 = (Bitstring.subbitstring bits (vm.w32vv_off+16)
                                              (vm.viral_section_off-vm.w32vv_off-16)) in
        let s5 = (Bitstring.subbitstring bits (vm.viral_section_off+320)
                                              (Bitstring.bitstring_length(bits)-vm.viral_section_off-320-vm.sz_raw_address*8)) in
        let bits2 = (BITSTRING {
                s1 : (Bitstring.bitstring_length(s1)) : bitstring;
                (* update number of sections *)
                (vm.n_sections-1) : 16 : littleendian;
                s2 : (Bitstring.bitstring_length(s2)) : bitstring;
                (* restore original entry point *)
                Int32.of_int(vm.old_ep) : 32 : littleendian;
                s3 : (Bitstring.bitstring_length(s3)) : bitstring;
                (* remove infection mark *)
                0 : 16;
                s4 : (Bitstring.bitstring_length(s4)) : bitstring;
                (* overwrite viral section, avoid false positives *)
                0_l : 32; 0_l : 32; 0_l : 32; 0_l : 32; 0_l : 32;
                0_l : 32; 0_l : 32; 0_l : 32; 0_l : 32; 0_l : 32;
                s5 : (Bitstring.bitstring_length(s5)) : bitstring
        }) in
        let _ = Bitstring.bitstring_to_file bits2 file in
        true
   | None ->
        false;;

let infected file =
  let bits = Bitstring.bitstring_of_file file in
  bitmatch bits with
  | { (* MZ signature *)
      "MZ" : 16 : string;
      e_lfanew : 32 : littleendian, offset(480);
      (* PE signature *)
      "PE" : 16 : string, offset(Int32.to_int(e_lfanew)*8);
      0 : 16;
      _ : 16 : bitstring;
      n_sections : 16 : littleendian, save_offset_to(n_sections_off);
      _ : 96 : bitstring;
      sz_opt_header : 16 : littleendian;
      _ : 16 : littleendian;
      (* optional header *)
      _ : 128 : bitstring;
      rva_ep : 32 : littleendian, save_offset_to(rva_ep_off);
      _ : 64 : bitstring;
      img_base : 32 : littleendian;
      _ : 160 : bitstring;
      (* infection mark *)
      0xd00d : 16 : littleendian, save_offset_to(w32vv_off);
      _ : (sz_opt_header-32)*8-176 : bitstring;
      (* walk all sections but last one *)
      _ : (n_sections-1)*320 : bitstring;
      (* virus section *)
      ".|Zan" : 40 : string, save_offset_to(viral_section_off);
      0 : 24;
      _ : 32 : bitstring;
      virt_address : 32 : littleendian;
      sz_raw_address : 32 : littleendian;
      raw_address : 32 : littleendian;
      _ : 96 : bitstring;
      charact : 16 : littleendian;
      _ : 8 : littleendian, offset(Int32.to_int(raw_address)*8);
      (* section start + 0x4c9 = old entry point *)
      _ : (Int32.to_int(0x4c9_l)-1)*8 : bitstring;
      old_ep : 32 : littleendian
    } ->
        (true, Some {n_sections        = n_sections;
                     n_sections_off    = n_sections_off;
                     sz_opt_header     = sz_opt_header;
                     rva_ep            = Int32.to_int rva_ep;
                     rva_ep_off        = rva_ep_off;
                     img_base          = Int32.to_int img_base;
                     w32vv_off         = w32vv_off;
                     viral_section_off = viral_section_off;
                     virt_address      = Int32.to_int virt_address;
                     sz_raw_address    = Int32.to_int sz_raw_address;
                     raw_address       = Int32.to_int raw_address;
                     charact           = charact;
                     old_ep            = Int32.to_int old_ep})
  | { _ } ->
        (false, None);;
end
