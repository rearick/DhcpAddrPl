require 'ipaddr'
require 'csv'
# Copyright 2017 Daniel Rearick
# Distributed under the terms of the GNU General Public License (GPL) v3.0

class DhcpAddrPl
  attr_reader :dhcp_dump, :active_scopes, :scope_ranges, :ipranges, :excluderanges, :dhcp_address_pool

  def initialize(target = nil, file = nil)
    if target && file == "file"
      @dhcp_dump = IO.readlines(target)
    elsif target && file
      @dhcp_dump = %x{netsh dhcp server \\\\\\\\"#{target}" dump}
      @dhcp_dump = @dhcp_dump.split("\r\n")
    end
    if @dhcp_dump
      @dhcp_dump.map! { |line| line.strip }
      @active_scopes = find_active_scopes
      @scope_ranges = find_scope_ranges
      @ipranges = find_ipranges
      @excluderanges = find_excluderanges
      @dhcp_address_pool = scope_exclude_delta(@ipranges, @excluderanges)
    else
      @dhcp_dump = []
      @active_scopes = []
      @scope_ranges = []
      @ipranges = []
      @excluderanges = []
      @dhcp_address_pool = []
    end
  end

protected

  def search(search_term)
    return_arry = []
    dhcp_dump = @dhcp_dump.dup
    case search_term
    when "set state 1"
      line_pattern = /Scope ([0-9]{1,3}\.){3}[0-9]{1,3} set state 1/
      extract_pattern = /([0-9]{1,3}\.){3}[0-9]{1,3}/
      dhcp_dump.each do |line|
        return_arry << line if line =~ line_pattern
      end
      return_arry.map! { |scope| extract_pattern.match(scope) }
      return_arry.map! { |net_id| net_id.to_s }
    when "add scope", "Add iprange", "add excluderange"
      extract_pattern = /([0-9]{1,3}\.){3}[0-9]{1,3}\s+([0-9]{1,3}\.){3}[0-9]{1,3}/
      @active_scopes.each do |net_id|
        case search_term
        when "add scope" then line_pattern = /add scope #{net_id}/
        when "Add iprange" then line_pattern = /Scope #{net_id} Add iprange/
        when "add excluderange" then line_pattern = /Scope #{net_id} add excluderange/
        end
        puts "Searching scope #{net_id} for #{search_term}"
        dhcp_dump_placeholder = 0
        dhcp_dump.each do |line|
          dhcp_dump_placeholder += 1
          if line =~ line_pattern
            return_arry << extract_pattern.match(line)
            return_arry[-1] = return_arry[-1].to_s.split
            case search_term
            when "add scope"
              return_arry[-1] = IPAddr.new("#{return_arry[-1][0]}/#{return_arry[-1][1]}")
              return_arry[-1] = return_arry[-1].to_range
            when "Add iprange", "add excluderange"
              return_arry[-1].map! { |address| IPAddr.new(address) }
              return_arry[-1] = Range.new(return_arry[-1][0],return_arry[-1][1])
            end
          end
          if line =~ /End   Add Excluderanges to the Scope : #{net_id}/
            break
          end
        end
        dhcp_dump_placeholder.times { dhcp_dump.shift }
      end
    end
    case search_term
    when "set state 1" then return_arry
    when "add scope", "Add iprange", "add excluderange" then return_arry = address_sort(return_arry)
    end
  end

  def find_active_scopes
    search("set state 1")
  end

  def find_scope_ranges
    search("add scope")
  end

  def find_ipranges
    search("Add iprange")
  end

  def find_excluderanges
    search("add excluderange")
  end

  def address_sort(ipaddr_objects)
    ipaddr_objects.sort_by! do |ipaddr_object|
      if ipaddr_object.class == Range && ipaddr_object.begin.class == IPAddr
        ipaddr_object.begin
      elsif ipaddr_object.class == IPAddr
        ipaddr_object
      else
        puts "Invalid object class passed to address_sort"
      end
    end
    ipaddr_objects
  end

  def scope_exclude_delta(ipranges, excluderanges)
    dhcp_address_pool = []
    ipranges = ipranges.dup
    excluderanges = excluderanges.dup
    iprange_hash = to_hash("hash of arrays", ipranges, excluderanges)
    iprange_hash.each do |iprange, scope_excluderanges|
      unless scope_excluderanges.empty?
        address_sort(scope_excluderanges)
        iteration = 0
        working_delta = []
        scope_excluderanges.each_with_index do |excluderange, index|
          iteration += 1
          case
          when iteration == 1
            delta = range_common(iprange, excluderange)[:unique1]
          when iteration > 1
            delta = range_common(working_delta[0], excluderange)[:unique1]
          end
          working_delta = delta.dup if delta.class == Array
          if delta.class != Array
            working_delta = []
            working_delta << delta.dup unless delta == nil
          end
          unless scope_excluderanges[index + 1] == nil
            dhcp_address_pool << working_delta.shift if working_delta.length > 1
          else
            working_delta.each { |range_or_addr| dhcp_address_pool << range_or_addr } unless working_delta.empty?
          end
        end
      else
        dhcp_address_pool << iprange
      end
    end
    dhcp_address_pool = range_concat(dhcp_address_pool)
  end

  def range_concat(ipaddr_objects)
    return_arry = []
    ipaddr_objects = ipaddr_objects.dup
    ipaddr_objects.each do |ipaddr_object|
      case
      when ipaddr_object.class == Range && return_arry[-1].class == IPAddr
        if return_arry[-1].succ == ipaddr_object.begin || return_arry[-1] == ipaddr_object.begin
          return_arry[-1] = Range.new(return_arry[-1], ipaddr_object.end)
        else
          return_arry << ipaddr_object
        end
      when ipaddr_object.class == IPAddr && return_arry[-1].class == Range
        if return_arry[-1].end.succ == ipaddr_object || return_arry[-1].end == ipaddr_object
          return_arry[-1] = Range.new(return_arry[-1].begin, ipaddr_object)
        elsif return_arry[-1].end >= ipaddr_object
          # Do nothing
        else
          return_arry << ipaddr_object
        end
      when ipaddr_object.class == IPAddr && return_arry[-1].class == IPAddr
        if return_arry[-1].succ == ipaddr_object || return_arry[-1] == ipaddr_object
          return_arry[-1] = Range.new(return_arry[-1], ipaddr_object)
        else
          return_arry << ipaddr_object
        end
      when ipaddr_object.class == Range && return_arry[-1].class == Range
        if return_arry[-1].end.succ >= ipaddr_object.begin && return_arry[-1].end <= ipaddr_object.end
          return_arry[-1] = Range.new(return_arry[-1].begin, ipaddr_object.end)
        elsif return_arry[-1].end > ipaddr_object.end
          # Do nothing
        else
          return_arry << ipaddr_object
        end
      when return_arry[-1].class == NilClass
        return_arry << ipaddr_object
      else
        puts "Invalid object class passed to range_concat"
      end
      if return_arry[-1].class == Range && return_arry[-1].begin == return_arry[-1].end
        return_arry[-1] = IPAddr.new(return_arry[-1].begin, return_arry[-1].begin.family)
      end
    end
    return_arry
  end

  def range_common(input1, input2)
    log_file = File.open("dhcpaddrpl.out", "a")
    input1 = input1.begin if input1.class == Range && input1.begin == input1.end
    input2 = input2.begin if input2.class == Range && input2.begin == input2.end
    result = {}
    case
    when input1.class == Range && input2.class == Range
      if input1 == input2
        result = {
          unique1: nil,
          common:  input1,
          unique2: nil
        }
      elsif input1.begin == input2.begin && input1.end > input2.end
        result = {
          unique1: Range.new(input2.end.succ, input1.end),
          common:  input2,
          unique2: nil
        }
      elsif input1.begin == input2.begin && input1.end < input2.end
        result = {
          unique1: nil,
          common:  input1,
          unique2: Range.new(input1.end.succ, input2.end)
        }
      elsif input1.begin < input2.begin && input1.end == input2.end
        result = {
          unique1: Range.new(input1.begin, Range.new(input1.begin, input2.begin).to_a[-2]),
          common:  input2,
          unique2: nil
        }
      elsif input1.begin > input2.begin && input1.end == input2.end
        result = {
          unique1: nil,
          common:  input1,
          unique2: Range.new(input2.begin, Range.new(input2.begin, input1.begin).to_a[-2])
        }
      elsif !input1.member?(input2.begin) && input1.member?(input2.end)
        result = {
          unique1: Range.new(input2.end.succ, input1.end),
          common:  Range.new(input1.begin, input2.end),
          unique2: Range.new(input2.begin, Range.new(input2.begin, input1.begin).to_a[-2])
        }
      elsif input1.member?(input2.begin) && !input1.member?(input2.end)
        result = {
          unique1: Range.new(input1.begin, Range.new(input1.begin, input2.begin).to_a[-2]),
          common:  Range.new(input2.begin, input1.end),
          unique2: Range.new(input1.end.succ, input2.end)
        }
      elsif input1.begin < input2.begin && input1.end > input2.end
        result = {
          unique1: [ Range.new(input1.begin, Range.new(input1.begin, input2.begin).to_a[-2]), Range.new(input2.end.succ, input1.end) ],
          common:  input2,
          unique2: nil
        }
      elsif input1.begin > input2.begin && input1.end < input2.end
        result = {
          unique1: nil,
          common:  input1,
          unique2: [ Range.new(input2.begin, Range.new(input2.begin, input1.begin).to_a[-2]), Range.new(input1.end.succ, input2.end) ]
        }
      else
        result = {
          unique1: input1,
          common:  nil,
          unique2: input2
        }
      end
    when input1.class == Range && input2.class == IPAddr
      if input1.begin < input2 && input1.end > input2
        result = {
          unique1: [ Range.new(input1.begin, Range.new(input1.begin, input2).to_a[-2]), Range.new(input2.succ, input1.end) ],
          common:  input2,
          unique2: nil
        }
      elsif input1.begin == input2
        result = {
          unique1: Range.new(input1.begin.succ, input1.end),
          common:  input2,
          unique2: nil
        }
      elsif input1.end == input2
        result = {
          unique1: Range.new(input1.begin, input1.to_a[-2]),
          common:  input2,
          unique2: nil
        }
      else
        result = {
          unique1: input1,
          common:  nil,
          unique2: input2
        }
      end
    when input1.class == IPAddr && input2.class == Range
      if input1 > input2.begin && input1 < input2.end
        result = {
          unique1: nil,
          common: input1,
          unique2: [ Range.new(input2.begin, Range.new(input2.begin, input1).to_a[-2]), Range.new(input1.succ, input2.end) ]
        }
      elsif input1 == input2.begin
        result = {
          unique1: nil,
          common:  input1,
          unique2: Range.new(input1.succ, input2.end)
        }
      elsif input1 == input2.end
        result = {
          unique1: nil,
          common:  input1,
          unique2: Range.new(input2.begin, input2.to_a[-2])
        }
      else
        result = {
          unique1: input1,
          common:  nil,
          unique2: input2
        }
      end
    when input1.class == IPAddr && input2.class == IPAddr
      if input1 == input2
        result = {
          unique1: nil,
          common:  input1,
          unique2: nil
        }
      else
        result = {
          unique1: input1,
          common:  nil,
          unique2: input2
        }
      end
    end
    result.each_key do |key|
      case
      when result[key].class == Range
        result[key] = result[key].begin if result[key].begin == result[key].end
      when result[key].class == Array
        result[key].each_with_index do |range, index|
          result[key][index] = result[key][index].begin if result[key][index].begin == result[key][index].end
        end
      end
    end
    result
  end

  def to_hash(function, merged_scope_ranges, ipaddr_arry_a, ipaddr_arry_b = [])
    scope_hash = {}
    ipaddr_arry_a = ipaddr_arry_a.dup
    case function
    when "hash of arrays"
      ipaddr_arry_a.concat(ipaddr_arry_b)
      ipaddr_arry_a = address_sort(ipaddr_arry_a)
      count = 0
      merged_scope_ranges.each do |range|
        ipaddr_arry_a_placeholder = []
        scope_hash[range] = []
        ipaddr_arry_a.each_with_index do |ipaddr_object, index|
          count += 1
          print "#{count}.."
          if ipaddr_object.class == Range && range.member?(ipaddr_object.begin)
            scope_hash[range] << ipaddr_object
            ipaddr_arry_a_placeholder << index
          elsif ipaddr_object.class == IPAddr && range.member?(ipaddr_object)
            scope_hash[range] << ipaddr_object
            ipaddr_arry_a_placeholder << index
          else
            break
          end
        end
        ipaddr_arry_a_placeholder.each { |index| ipaddr_arry_a[index, 1] = nil }
        ipaddr_arry_a.compact!
      end
    when "hash of hashes"
      ipaddr_arry_b = ipaddr_arry_b.dup
      count = 0
      merged_scope_ranges.each do |range|
        ipaddr_arry_a_placeholder = []
        scope_hash[range] = {}
        ipaddr_arry_a.each_with_index do |ipaddr_object, index|
          count += 1
          print "#{count}.."
          if ipaddr_object.class == Range && range.member?(ipaddr_object.begin)
            scope_hash[range] = { ipaddr_object => [] }
            ipaddr_arry_a_placeholder << index
          else
            break
          end
        end
        ipaddr_arry_a_placeholder.each { |index| ipaddr_arry_a[index, 1] = nil }
        ipaddr_arry_a.compact!
      end
      count = 0
      scope_hash.each_value do |hash|
        ipaddr_arry_b_placeholder = []
        ipaddr_arry_b.each_with_index do |ipaddr_object, index|
          count += 1
          print "#{count}.."
          match = true
          hash.each do |iprange, array|
            if ipaddr_object.class == Range && iprange.member?(ipaddr_object.begin)
              array << ipaddr_object
              ipaddr_arry_b_placeholder << index
            elsif ipaddr_object.class == IPAddr && iprange.member?(ipaddr_object)
              array << ipaddr_object
              ipaddr_arry_b_placeholder << index
            else
              match = false
              break
            end
          end
          break unless match
        end
        ipaddr_arry_b_placeholder.each { |index| ipaddr_arry_b[index, 1] = nil }
        ipaddr_arry_b.compact!
      end
    end
    scope_hash
  end

  def range_recon(function, merged_scope_ranges, ipaddr_arry_a, ipaddr_arry_b, ipaddr_arry_c = [], ipaddr_arry_d = [])
    return_arry = []
    case function
    when "concat"
      scope_hash = to_hash("hash of arrays", merged_scope_ranges, ipaddr_arry_a, ipaddr_arry_b)
    when "return common"
      scope_hash_a = to_hash("hash of hashes", merged_scope_ranges, ipaddr_arry_a, ipaddr_arry_c)
      scope_hash_b = to_hash("hash of hashes", merged_scope_ranges, ipaddr_arry_b, ipaddr_arry_d)
      scope_hash = {}
      scope_hash_a.each_key do |range|
        scope_hash[range] = []
        if !scope_hash_a[range].empty? && !scope_hash_b[range].empty?
          scope_hash_a[range].each do |iprange_a, excluderanges_a|
            scope_hash_b[range].each do |iprange_b, excluderanges_b|
              iprange_cmprsn = range_common(iprange_a, iprange_b)
              excluderanges_a.each do |range_a|
                scope_hash[range] << range_common(iprange_cmprsn[:unique1], range_a)[:common]
                excluderanges_b.each { |range_b| scope_hash[range] << range_common(range_a, range_b)[:common] }
              end
              excluderanges_b.each { |range_b| scope_hash[range] << range_common(iprange_cmprsn[:unique2], range_b)[:common] }
              scope_hash[range].compact!
            end
          end
        elsif !scope_hash_a[range].empty?
          scope_hash_a[range].each_value do |excluderanges_a|
            excluderanges_a.each { |range_a| scope_hash[range] << range_a }
          end
        elsif !scope_hash_b[range].empty?
          scope_hash_b[range].each_value do |excluderanges_b|
            excluderanges_b.each { |range_b| scope_hash[range] << range_b }
          end
        end
      end
    end
    scope_hash.each_value do |ranges|
      address_sort(ranges)
      ranges.uniq!
      ranges = range_concat(ranges) if ranges.length > 1
      ranges.each { |range| return_arry << range }
    end
    return_arry
  end

  def str_to_ip(string)
    string = IPAddr.new(string)
  end

  def merge_scopes(scope_ls_a, scope_ls_b)
    scope_ls_a = scope_ls_a.dup
    scope_ls_b = scope_ls_b.dup
    if scope_ls_a.first.class == String && scope_ls_b.first.class == String
      scope_ls_a.map! { |net_id| str_to_ip(net_id) }
      scope_ls_b.map! { |net_id| str_to_ip(net_id) }
    end
    scope_ls_ab = []
    scope_ls_ab.concat(scope_ls_a)
    scope_ls_ab.concat(scope_ls_b)
    if scope_ls_ab.first.class == IPAddr
      scope_ls_ab.sort!.uniq!
      scope_ls_ab.map! { |net_id| net_id.to_s }
    else
      address_sort(scope_ls_ab)
      scope_ls_ab.uniq!
    end
    scope_ls_ab
  end

  def dhcp_dump=(str_arry)
    @dhcp_dump = str_arry
  end

  def active_scopes=(net_ids)
    @active_scopes = net_ids
  end

  def scope_ranges=(ipaddr_ranges)
    @scope_ranges = ipaddr_ranges
  end

  def ipranges=(ipaddr_objects)
    @ipranges = ipaddr_objects
  end

  def excluderanges=(ipaddr_objects)
    @excluderanges = ipaddr_objects
  end

  def dhcp_address_pool=(ipaddr_objects)
    @dhcp_address_pool = ipaddr_objects
  end

public

  def to_s
    str = ""
    @dhcp_dump.each { |line| str.concat("#{line}\r\n") }
    str
  end

  def recon(dhcpaddrpl_object)
    recon_res = DhcpAddrPl.new
    puts "#{recon_res.inspect}"
    recon_res.dhcp_dump = [ "Reconciled DHCP Address Pool" ]
    puts "#{recon_res.dhcp_dump.inspect}"
    recon_res.active_scopes = merge_scopes(@active_scopes, dhcpaddrpl_object.active_scopes)
    puts "Active scopes merged..."
    recon_res.scope_ranges = merge_scopes(@scope_ranges, dhcpaddrpl_object.scope_ranges)
    puts "Scope ranges merged..."
    recon_res.ipranges = range_recon("concat", recon_res.scope_ranges, @ipranges, dhcpaddrpl_object.ipranges)
    puts "ipranges merged"
    recon_res.excluderanges = range_recon("return common", recon_res.scope_ranges, @ipranges, dhcpaddrpl_object.ipranges, @excluderanges, dhcpaddrpl_object.excluderanges)
    puts "excluderanges merged"
    recon_res.dhcp_address_pool = scope_exclude_delta(recon_res.ipranges, recon_res.excluderanges)
    recon_res
  end

  def write_csv(file_name = "dhcp_recon_#{Time.now.strftime("%F")}.csv", scope_ranges = [])
    validation_failed = false
    scope_ranges.each do |range|
      if range.class == Range && range.begin.class == IPAddr
        validation_failed = false
      else
        validation_failed = true
        break
      end
    end
    scope_ranges = @scope_ranges.dup if scope_ranges.empty? || validation_failed
    ipranges = to_hash("hash of arrays", @scope_ranges, @ipranges)
    excluderanges = to_hash("hash of arrays", @scope_ranges, @excluderanges)
    dhcp_address_pool = to_hash("hash of arrays", @scope_ranges, @dhcp_address_pool)
    csv_array = [ [ "Scope", "IP Range", "Exclude Range", "Address Pool" ] ]
    scope_ranges.each do |range|
      high_num = 0
      [ ipranges[range], excluderanges[range], dhcp_address_pool[range] ].each { |array| high_num = array.length if array.length > high_num }
      scope_label = high_num.times.map { range }
      temp_array = scope_label.zip(ipranges[range], excluderanges[range], dhcp_address_pool[range])
      temp_array.each { |row| csv_array << row }
    end
    CSV.open(file_name, "w") do |csv|
      csv_array.each { |row| csv << row }
    end
  end

  def validate_recon(dhcpaddrpl_a, dhcpaddrpl_b)
    recon_test = "Reconciled DHCP Address Pool"
    if @dhcp_dump[0] == recon_test && dhcpaddrpl_a != recon_test && dhcpaddrpl_b != recon_test
      sample = 30.times.map { rand(@dhcp_address_pool.length - 1) }
      sample.sort!
      sample.map! { |index| @dhcp_address_pool[index] }
      address_sort(sample)
      sample = to_hash("hash of arrays", @scope_ranges, sample)
      sample = sample.each.map { |key, value| key unless value.empty? }
      sample.compact!
      ipranges_a = to_hash("hash of arrays", @scope_ranges, dhcpaddrpl_a.ipranges)
      ipranges_b = to_hash("hash of arrays", @scope_ranges, dhcpaddrpl_b.ipranges)
      excluderanges_a = to_hash("hash of arrays", @scope_ranges, dhcpaddrpl_a.excluderanges)
      excluderanges_b = to_hash("hash of arrays", @scope_ranges, dhcpaddrpl_b.excluderanges)
      dhcp_address_pool = to_hash("hash of arrays", @scope_ranges, @dhcp_address_pool)
      csv_array = [ [ "Scope", "IP Range Svr 1", "IP Range Svr 2", "Exclude Range Svr 1", "Exclude Range Svr 2", "Address Pool", "Pass/Fail" ] ]
      sample.each do |range|
        high_num = 0
        [ ipranges_a[range], ipranges_b[range], excluderanges_a[range], excluderanges_b[range], dhcp_address_pool[range] ].each do |array|
          high_num = array.length if array.length > high_num
        end
        scope_label = high_num.times.map { range }
        temp_array = scope_label.zip(ipranges_a[range], ipranges_b[range], excluderanges_a[range], excluderanges_b[range], dhcp_address_pool[range])
        temp_array.each { |row| csv_array << row }
      end
      CSV.open("dhcp_recon_validation_#{Time.now.strftime("%F")}.csv", "w") do |csv|
        csv_array.each { |row| csv << row }
      end
    else
      puts "Invalid argument(s) passed to the validate method!"
    end
  end

  def dup
    copy = DhcpAddrPl.new
    copy.dhcp_dump = @dhcp_dump.dup
    copy.active_scopes = @active_scopes.dup
    copy.scope_ranges = @scope_ranges.dup
    copy.ipranges = @ipranges.dup
    copy.excluderanges = @excluderanges.dup
    copy.dhcp_address_pool = @dhcp_address_pool.dup
    copy
  end
end
