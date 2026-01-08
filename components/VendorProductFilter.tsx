import React, { useState, useRef, useEffect, useCallback } from 'react';
import { X, Building2, Package, ChevronDown, Loader2 } from 'lucide-react';

interface VendorResult {
  vendor: string;
  count: number;
}

interface ProductResult {
  product: string;
  vendor: string;
  count: number;
}

interface VendorProductFilterProps {
  selectedVendors: string[];
  selectedProducts: string[];
  onVendorsChange: (vendors: string[]) => void;
  onProductsChange: (products: string[]) => void;
}

const VendorProductFilter: React.FC<VendorProductFilterProps> = ({
  selectedVendors,
  selectedProducts,
  onVendorsChange,
  onProductsChange
}) => {
  // Vendor state
  const [vendorQuery, setVendorQuery] = useState('');
  const [vendorResults, setVendorResults] = useState<VendorResult[]>([]);
  const [vendorLoading, setVendorLoading] = useState(false);
  const [showVendorDropdown, setShowVendorDropdown] = useState(false);
  const vendorInputRef = useRef<HTMLInputElement>(null);
  const vendorDropdownRef = useRef<HTMLDivElement>(null);

  // Product state
  const [productQuery, setProductQuery] = useState('');
  const [productResults, setProductResults] = useState<ProductResult[]>([]);
  const [productLoading, setProductLoading] = useState(false);
  const [showProductDropdown, setShowProductDropdown] = useState(false);
  const productInputRef = useRef<HTMLInputElement>(null);
  const productDropdownRef = useRef<HTMLDivElement>(null);

  // Debounced vendor search
  const searchVendors = useCallback(async (query: string) => {
    if (query.length < 2) {
      setVendorResults([]);
      return;
    }
    setVendorLoading(true);
    try {
      const res = await fetch(`/api/vendors?q=${encodeURIComponent(query)}&limit=15`);
      if (res.ok) {
        const data = await res.json();
        setVendorResults(data);
      }
    } catch (err) {
      console.error('Error searching vendors:', err);
    } finally {
      setVendorLoading(false);
    }
  }, []);

  // Debounced product search
  const searchProducts = useCallback(async (query: string) => {
    if (query.length < 2) {
      setProductResults([]);
      return;
    }
    setProductLoading(true);
    try {
      // If vendors are selected, filter products by those vendors
      const vendorParam = selectedVendors.length === 1 ? `&vendor=${encodeURIComponent(selectedVendors[0])}` : '';
      const res = await fetch(`/api/products?q=${encodeURIComponent(query)}&limit=15${vendorParam}`);
      if (res.ok) {
        const data = await res.json();
        setProductResults(data);
      }
    } catch (err) {
      console.error('Error searching products:', err);
    } finally {
      setProductLoading(false);
    }
  }, [selectedVendors]);

  // Debounce vendor input
  useEffect(() => {
    const timer = setTimeout(() => {
      searchVendors(vendorQuery);
    }, 300);
    return () => clearTimeout(timer);
  }, [vendorQuery, searchVendors]);

  // Debounce product input
  useEffect(() => {
    const timer = setTimeout(() => {
      searchProducts(productQuery);
    }, 300);
    return () => clearTimeout(timer);
  }, [productQuery, searchProducts]);

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (vendorDropdownRef.current && !vendorDropdownRef.current.contains(e.target as Node)) {
        setShowVendorDropdown(false);
      }
      if (productDropdownRef.current && !productDropdownRef.current.contains(e.target as Node)) {
        setShowProductDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const addVendor = (vendor: string) => {
    if (!selectedVendors.includes(vendor)) {
      onVendorsChange([...selectedVendors, vendor]);
    }
    setVendorQuery('');
    setShowVendorDropdown(false);
    setVendorResults([]);
  };

  const removeVendor = (vendor: string) => {
    onVendorsChange(selectedVendors.filter(v => v !== vendor));
  };

  const addProduct = (product: string) => {
    if (!selectedProducts.includes(product)) {
      onProductsChange([...selectedProducts, product]);
    }
    setProductQuery('');
    setShowProductDropdown(false);
    setProductResults([]);
  };

  const removeProduct = (product: string) => {
    onProductsChange(selectedProducts.filter(p => p !== product));
  };

  const clearAll = () => {
    onVendorsChange([]);
    onProductsChange([]);
  };

  const hasSelections = selectedVendors.length > 0 || selectedProducts.length > 0;

  return (
    <div className="space-y-4">
      {/* Header with clear button */}
      <div className="flex items-center justify-between">
        <label className="block text-xs font-semibold text-gray-400 mono">VENDOR / PRODUCT FILTER</label>
        {hasSelections && (
          <button
            onClick={clearAll}
            className="text-xs text-gray-500 hover:text-cyan-400 mono transition-colors"
          >
            CLEAR ALL
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Vendor Typeahead */}
        <div className="relative" ref={vendorDropdownRef}>
          <div className="flex items-center gap-2 mb-2">
            <Building2 className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
            <span className="text-xs text-gray-500 mono">VENDORS</span>
          </div>
          <div className="relative">
            <input
              ref={vendorInputRef}
              type="text"
              placeholder="Search vendors..."
              className="w-full px-3 py-2.5 pr-8 border rounded-lg bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm focus:outline-none focus:border-cyan-500"
              style={{ borderColor: 'var(--cyber-border)' }}
              value={vendorQuery}
              onChange={(e) => setVendorQuery(e.target.value)}
              onFocus={() => setShowVendorDropdown(true)}
            />
            {vendorLoading ? (
              <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 animate-spin" />
            ) : (
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
            )}
          </div>

          {/* Vendor Dropdown */}
          {showVendorDropdown && vendorResults.length > 0 && (
            <div
              className="absolute top-full left-0 right-0 mt-1 max-h-48 overflow-y-auto rounded-lg border z-50"
              style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)'
              }}
            >
              {vendorResults.map((item) => (
                <button
                  key={item.vendor}
                  onClick={() => addVendor(item.vendor)}
                  className={`w-full px-3 py-2 text-left text-sm mono transition-all hover:bg-cyan-500/10 flex items-center justify-between ${
                    selectedVendors.includes(item.vendor) ? 'text-cyan-400' : 'text-gray-300'
                  }`}
                >
                  <span className="truncate">{item.vendor}</span>
                  <span className="text-xs text-gray-500 ml-2">{item.count.toLocaleString()}</span>
                </button>
              ))}
            </div>
          )}

          {/* Selected Vendors */}
          {selectedVendors.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {selectedVendors.map((vendor) => (
                <span
                  key={vendor}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs mono bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                >
                  <span className="truncate max-w-[120px]">{vendor}</span>
                  <button
                    onClick={() => removeVendor(vendor)}
                    className="hover:text-cyan-300 transition-colors"
                  >
                    <X className="h-3 w-3" strokeWidth={2} />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Product Typeahead */}
        <div className="relative" ref={productDropdownRef}>
          <div className="flex items-center gap-2 mb-2">
            <Package className="h-4 w-4 text-gray-500" strokeWidth={1.5} />
            <span className="text-xs text-gray-500 mono">PRODUCTS</span>
          </div>
          <div className="relative">
            <input
              ref={productInputRef}
              type="text"
              placeholder="Search products..."
              className="w-full px-3 py-2.5 pr-8 border rounded-lg bg-gray-900/50 text-gray-100 placeholder-gray-600 mono text-sm focus:outline-none focus:border-cyan-500"
              style={{ borderColor: 'var(--cyber-border)' }}
              value={productQuery}
              onChange={(e) => setProductQuery(e.target.value)}
              onFocus={() => setShowProductDropdown(true)}
            />
            {productLoading ? (
              <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 animate-spin" />
            ) : (
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
            )}
          </div>

          {/* Product Dropdown */}
          {showProductDropdown && productResults.length > 0 && (
            <div
              className="absolute top-full left-0 right-0 mt-1 max-h-48 overflow-y-auto rounded-lg border z-50"
              style={{
                background: 'var(--cyber-surface)',
                borderColor: 'var(--cyber-border)'
              }}
            >
              {productResults.map((item, idx) => (
                <button
                  key={`${item.vendor}-${item.product}-${idx}`}
                  onClick={() => addProduct(item.product)}
                  className={`w-full px-3 py-2 text-left text-sm mono transition-all hover:bg-cyan-500/10 ${
                    selectedProducts.includes(item.product) ? 'text-cyan-400' : 'text-gray-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="truncate">{item.product}</span>
                    <span className="text-xs text-gray-500 ml-2">{item.count.toLocaleString()}</span>
                  </div>
                  <div className="text-xs text-gray-600 truncate">{item.vendor}</div>
                </button>
              ))}
            </div>
          )}

          {/* Selected Products */}
          {selectedProducts.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {selectedProducts.map((product) => (
                <span
                  key={product}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs mono bg-purple-500/20 text-purple-400 border border-purple-500/30"
                >
                  <span className="truncate max-w-[120px]">{product}</span>
                  <button
                    onClick={() => removeProduct(product)}
                    className="hover:text-purple-300 transition-colors"
                  >
                    <X className="h-3 w-3" strokeWidth={2} />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default VendorProductFilter;
